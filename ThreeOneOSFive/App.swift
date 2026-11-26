import SwiftUI

@main
struct ThreeOneOSFiveApp: App {
    @StateObject private var appState = AppState()
    @StateObject private var patchDraftCoordinator = PatchDraftCoordinator()
    @StateObject private var fileOperationCoordinator = FileOperationCoordinator()
    @StateObject private var patchStore = PatchProjectStore()
    @StateObject private var keyAuth = KeyAuthManager.shared

    init() {
        setupLogCapture()
        _ = LocalDevBridge.shared
        log("app: Tobi AIM launching — iOS \(AppInfo.osVersion) (\(AppInfo.osBuild)) \(AppInfo.machineName)")
    }

    private var language: AppLanguage { .vietnamese }

    var body: some Scene {
        WindowGroup {
            SecurityGateRootView(
                appState: appState,
                patchDraftCoordinator: patchDraftCoordinator,
                fileOperationCoordinator: fileOperationCoordinator,
                patchStore: patchStore,
                keyAuth: keyAuth
            )
            .environment(\.appLanguage, language)
            .environment(\.locale, language.locale)
            .preferredColorScheme(.dark)
        }
    }
}

/// Dedicated View wrapper owning `@ObservedObject` subscription to `KeyAuthManager.shared`
/// so SwiftUI reliably observes status/phase transitions even during early Scene startup.
private struct SecurityGateRootView: View {
    @ObservedObject var appState: AppState
    @ObservedObject var patchDraftCoordinator: PatchDraftCoordinator
    @ObservedObject var fileOperationCoordinator: FileOperationCoordinator
    @ObservedObject var patchStore: PatchProjectStore
    @ObservedObject var keyAuth: KeyAuthManager
    @State private var showOnboarding = OnboardingStore.shouldShow()
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        ZStack {
            switch keyAuth.gatePhase {
            case .checking:
                SecurityCheckingView(
                    message: keyAuth.statusMessage,
                    elapsedSeconds: keyAuth.checkingElapsedSeconds,
                    onRetry: { keyAuth.bootstrapCheck(force: true) }
                )
                .transition(.opacity)
            case .connectionError(let message):
                SecurityLockoutView(
                    mode: .connectionError(message: message),
                    onRetry: { keyAuth.bootstrapCheck(force: true) }
                )
                .transition(.opacity)
            case .serverClosed(let message):
                SecurityLockoutView(
                    mode: .serverClosed(message: message),
                    onRetry: { keyAuth.bootstrapCheck(force: true) }
                )
                .transition(.opacity)
            case .deviceBanned(let reason, let hwid):
                SecurityLockoutView(
                    mode: .deviceBanned(reason: reason, hwid: hwid),
                    onRetry: { keyAuth.bootstrapCheck(force: true) }
                )
                .transition(.opacity)
            case .forceUpdate(let minVer, let latestVer, let downloadURL, let message):
                SecurityLockoutView(
                    mode: .forceUpdate(
                        minVersion: minVer,
                        latestVersion: latestVer,
                        downloadURL: downloadURL,
                        message: message
                    ),
                    onRetry: { keyAuth.bootstrapCheck(force: true) }
                )
                .transition(.opacity)
            case .tampered(let message):
                SecurityLockoutView(
                    mode: .tampered(message: message),
                    onRetry: { keyAuth.bootstrapCheck(force: true) }
                )
                .transition(.opacity)
            case .requiresKey:
                KeyGatekeeperView(keyAuth: keyAuth)
                    .transition(.opacity)
            case .unlocked(let ticket):
                if SecCoreBridge.shared.isActiveTicketValid(ticket) {
                    ContentView()
                        .environmentObject(appState)
                        .environmentObject(patchDraftCoordinator)
                        .environmentObject(fileOperationCoordinator)
                        .environmentObject(patchStore)
                        .opacity(showOnboarding ? 0 : 1)
                        .allowsHitTesting(!showOnboarding)
                        .onOpenURL { url in
                            patchDraftCoordinator.presentImport(url)
                        }

                    if showOnboarding {
                        OnboardingView {
                            OnboardingStore.markCompleted()
                            withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.24)) {
                                showOnboarding = false
                            }
                            appState.detectSupport()
                        }
                        .transition(
                            reduceMotion
                                ? .opacity
                                : .opacity.combined(with: .scale(scale: 0.98))
                        )
                        .zIndex(1)
                    }
                } else {
                    KeyGatekeeperView(keyAuth: keyAuth)
                        .transition(.opacity)
                        .onAppear {
                            keyAuth.checkExpirationNow()
                        }
                }
            }
        }
        .onAppear {
            keyAuth.startBootstrapIfNeeded()
            if !showOnboarding && keyAuth.activeVerifiedTicket != nil {
                appState.detectSupport()
            }
        }
        .task {
            keyAuth.startBootstrapIfNeeded()
        }
        .onChange(of: scenePhase) { phase in
            if phase == .active {
                keyAuth.verifyLiveSessionOnForeground()
                if !showOnboarding && keyAuth.activeVerifiedTicket != nil {
                    appState.detectSupport()
                }
            }
        }
        .onChange(of: keyAuth.gatePhase) { phase in
            if case .unlocked(let t) = phase, SecCoreBridge.shared.isActiveTicketValid(t), !showOnboarding {
                appState.detectSupport()
            }
        }
    }
}

class AppState: ObservableObject {
    @Published var exploitStatus: ExploitStatus = .notStarted
    @Published var unsupportedMessage: String?
    @Published var kernelExploitRunning = false

    private var autoRunAttempted = false

    var kernelExploitApplicable: Bool {
        KernelExploit.isApplicable(
            major: AppInfo.versionTuple.major,
            minor: AppInfo.versionTuple.minor,
            patch: AppInfo.versionTuple.patch,
            build: AppInfo.osBuild
        )
    }

    var isSupported: Bool { unsupportedMessage == nil }

    func detectSupport() {
        let v = AppInfo.versionTuple
        let supported = ExploitSupportPolicy.isSupported(
            major: v.major,
            minor: v.minor,
            patch: v.patch,
            build: AppInfo.osBuild
        )
#if targetEnvironment(simulator)
        if ProcessInfo.processInfo.arguments.contains("--simulate-access") {
            exploitStatus = .success(method: "Simulator preview")
        }
#endif

        unsupportedMessage = supported ? nil : "iOS \(AppInfo.osVersion) (\(AppInfo.osBuild))"
        if let unsupportedMessage {
            exploitStatus = .unsupported(unsupportedMessage)
            return
        }

        let applicable = KernelExploit.isApplicable(
            major: v.major,
            minor: v.minor,
            patch: v.patch,
            build: AppInfo.osBuild
        )
        guard applicable else { return }

        refreshKernelExploitStatus()
        maybeAutoRunKernelExploit()
    }

    private func maybeAutoRunKernelExploit() {
        let v = AppInfo.versionTuple
        guard ExploitSupportPolicy.supportsKernelExploit(major: v.major, minor: v.minor, patch: v.patch) else {
            return
        }
        guard !kernelExploitRunning,
              !exploitStatus.isSuccess,
              !exploitStatus.isFailed,
              !autoRunAttempted else { return }
        autoRunAttempted = true
        log("app: starting kernel exploit automatically")
        runKernelExploitIfNeeded()
    }

    private func refreshKernelExploitStatus() {
        guard !kernelExploitRunning else { return }

        if KernelExploit.requiresSandboxEscape {
            if KernelExploit.hasSandboxAccess() {
                if !exploitStatus.isSuccess {
                    exploitStatus = .success(method: "kexploit")
                    log("app: existing sandbox access is still active; skipping kernel exploit")
                }
            } else if exploitStatus.isSuccess {
                exploitStatus = .notStarted
                log("app: sandbox access is no longer active")
            }
        }
    }

    func runKernelExploitIfNeeded() {
        refreshKernelExploitStatus()
        guard !kernelExploitRunning,
              !exploitStatus.isSuccess,
              !exploitStatus.isFailed else { return }
        kernelExploitRunning = true
        exploitStatus = .notStarted
        log("app: running kernel exploit on background...")
        DispatchQueue.global(qos: .userInitiated).async {
            let ok = KernelExploit.run()
            DispatchQueue.main.async {
                self.kernelExploitRunning = false
                if ok {
                    self.exploitStatus = .success(method: "kexploit")
                    if KernelExploit.requiresSandboxEscape {
                        log("app: kernel exploit success — sandbox access verified")
                    } else {
                        log("app: kernel exploit success — kernel access active")
                    }
                } else {
                    self.exploitStatus = .failed(method: "kexploit", code: -1)
                    log("app: kernel exploit failed — relaunch the app before retrying")
                }
            }
        }
    }
}
