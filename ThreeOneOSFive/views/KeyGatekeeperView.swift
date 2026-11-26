import SwiftUI

enum SecurityGatePhase: Equatable {
    case checking
    case connectionError(message: String)
    case serverClosed(message: String)
    case deviceBanned(reason: String, hwid: String)
    case forceUpdate(minVersion: String, latestVersion: String, downloadURL: String, message: String)
    case tampered(message: String)
    case requiresKey
    case unlocked(RuntimeSessionTicket)
}

final class KeyAuthManager: ObservableObject {
    static let shared = KeyAuthManager()

    @Published var gatePhase: SecurityGatePhase = .checking
    @Published var statusMessage: String = "Đang thiết lập kênh bảo mật đầu cuối..."
    @Published var currentKey: String = ""
    @Published var expiryDateText: String = ""
    @Published var exactExpiryDateText: String = ""
    @Published var remainingCountdownText: String = ""
    @Published var secondsRemaining: TimeInterval = 0
    @Published var isPermanent: Bool = false
    @Published var role: String = "VIP"
    @Published var deviceSlotsText: String = "1/1 máy"
    @Published var isVerifying: Bool = false
    @Published var errorMessage: String? = nil
    @Published var deviceHWID: String = ""
    @Published var checkingElapsedSeconds: Int = 0
    @Published var presetStatusesByFileName: [String: V3PresetStatus] = [:]

    func presetStatus(for fileName: String) -> V3PresetStatus? {
        if let direct = presetStatusesByFileName[fileName] {
            return direct
        }
        let target = fileName.lowercased()
        return presetStatusesByFileName.values.first { $0.fileName.lowercased() == target }
    }

    private func updatePresetStatuses(_ statuses: [String: V3PresetStatus]) {
        guard !statuses.isEmpty else { return }
        presetStatusesByFileName = statuses
    }

    private var expirationDate: Date? = nil
    private var countdownTimer: Timer? = nil
    private var heartbeatTimer: Timer? = nil
    private var checkingTimer: Timer? = nil
    private var bootstrapGeneration: UInt64 = 0
    private var activationGeneration: UInt64 = 0
    private var isBootstrapping: Bool = false
    private let supportURLString = "https://tobivn.chickenkiller.com"

    var activeVerifiedTicket: RuntimeSessionTicket? {
        if case .unlocked(let ticket) = gatePhase, SecCoreBridge.shared.isActiveTicketValid(ticket) {
            return ticket
        }
        return nil
    }

    private init() {
        DispatchQueue.main.async {
            self.startBootstrapIfNeeded()
        }
    }

    func startBootstrapIfNeeded() {
        DispatchQueue.main.async {
            if case .checking = self.gatePhase, !self.isBootstrapping {
                self.bootstrapCheck(force: false)
            }
        }
    }

    func handleCheckingTimeoutFallback() {
        DispatchQueue.main.async {
            guard case .checking = self.gatePhase else {
                self.stopCheckingTimer()
                return
            }
            self.stopCheckingTimer()
            self.bootstrapGeneration &+= 1
            self.activationGeneration &+= 1
            self.isBootstrapping = false
            self.isVerifying = false
            SecCoreBridge.shared.wipeSession()
            let msg = "Quá thời gian thiết lập kênh bảo mật đầu cuối (12s). Vui lòng kiểm tra kết nối mạng và thử lại."
            self.errorMessage = msg
            self.gatePhase = .connectionError(message: msg)
        }
    }

    private func startCheckingTimer() {
        stopCheckingTimer()
        checkingElapsedSeconds = 0
        let timer = Timer(timeInterval: 1.0, repeats: true) { [weak self] _ in
            guard let self else { return }
            guard case .checking = self.gatePhase else {
                self.stopCheckingTimer()
                return
            }
            self.checkingElapsedSeconds += 1
            if self.checkingElapsedSeconds >= 12 {
                self.handleCheckingTimeoutFallback()
            }
        }
        RunLoop.main.add(timer, forMode: .common)
        checkingTimer = timer
    }

    private func stopCheckingTimer() {
        checkingTimer?.invalidate()
        checkingTimer = nil
    }

    /// Runs mandatory zero-trust preflight (Kill-Switch + Force Update + Integrity), then silent key auth if present.
    func bootstrapCheck(force: Bool = true) {
        let performOnMain = {
            if !force && self.isBootstrapping {
                return
            }
            if force {
                self.activationGeneration &+= 1
                self.isVerifying = false
            }
            self.bootstrapGeneration &+= 1
            let gen = self.bootstrapGeneration
            self.isBootstrapping = true
            self.errorMessage = nil
            self.statusMessage = "Đang xác thực trạng thái máy chủ & phiên bản..."
            if !self.isVerifying {
                self.gatePhase = .checking
                self.startCheckingTimer()
            }

            // Fail-safe watchdog timeout: guarantees infinite Checking spinner never stalls UI.
            DispatchQueue.main.asyncAfter(deadline: .now() + 12.0) { [weak self] in
                guard let self, self.isBootstrapping, self.bootstrapGeneration == gen else { return }
                self.stopCheckingTimer()
                self.isBootstrapping = false
                self.isVerifying = false
                SecCoreBridge.shared.wipeSession()
                let msg = "Quá thời gian kết nối máy chủ bảo mật (12s). Vui lòng kiểm tra mạng và thử lại."
                self.errorMessage = msg
                self.gatePhase = .connectionError(message: msg)
            }

            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                let fp = SecCoreBridge.shared.deviceFingerprint()
                let savedKey = KeychainLicenseVault.loadLicenseKey()
                let preflight = SecCoreBridge.shared.preflight()
                DispatchQueue.main.async {
                    guard let self, self.bootstrapGeneration == gen else { return }
                    if self.deviceHWID.isEmpty {
                        self.deviceHWID = fp
                    }
                    if !savedKey.isEmpty && self.currentKey.isEmpty {
                        self.currentKey = savedKey
                    }
                    guard self.isBootstrapping else { return }
                    self.isBootstrapping = false
                    switch preflight {
                    case .serverClosed(let msg):
                        self.lockOut(to: .serverClosed(message: msg))
                    case .deviceBanned(let reason, let hwid):
                        self.lockOut(to: .deviceBanned(reason: reason, hwid: hwid))
                    case .forceUpdate(let minV, let latV, let url, let msg):
                        self.lockOut(to: .forceUpdate(minVersion: minV, latestVersion: latV, downloadURL: url, message: msg))
                    case .tampered(let msg):
                        self.lockOut(to: .tampered(message: msg))
                    case .preflightOpen(_, _, let presetStatuses):
                        self.updatePresetStatuses(presetStatuses)
                        if !savedKey.isEmpty {
                            self.currentKey = savedKey
                            self.activateKey(savedKey, isSilent: true)
                        } else {
                            self.stopCheckingTimer()
                            self.gatePhase = .requiresKey
                        }
                    case .cryptoError(let msg), .networkError(let msg):
                        self.stopCheckingTimer()
                        SecCoreBridge.shared.wipeSession()
                        self.errorMessage = msg
                        self.gatePhase = .connectionError(message: msg)
                    case .denied(_, let msg):
                        self.stopCheckingTimer()
                        SecCoreBridge.shared.wipeSession()
                        self.errorMessage = msg
                        self.gatePhase = .connectionError(message: msg)
                    case .unlocked:
                        self.stopCheckingTimer()
                        SecCoreBridge.shared.wipeSession()
                        self.gatePhase = .connectionError(message: "Phản hồi kiểm tra máy chủ không hợp lệ.")
                    }
                }
            }
        }

        if Thread.isMainThread {
            performOnMain()
        } else {
            DispatchQueue.main.async(execute: performOnMain)
        }
    }

    func activateKey(_ rawKey: String, isSilent: Bool = false) {
        let trimmed = rawKey.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            DispatchQueue.main.async {
                self.isVerifying = false
                self.errorMessage = "Vui lòng nhập mã Key bản quyền!"
                self.gatePhase = .requiresKey
            }
            return
        }

        DispatchQueue.main.async {
            self.activationGeneration &+= 1
            let gen = self.activationGeneration
            self.isVerifying = true
            self.errorMessage = nil
            if isSilent {
                self.statusMessage = "Đang xác thực mã Key bản quyền..."
                self.gatePhase = .checking
                self.startCheckingTimer()
            }

            DispatchQueue.main.asyncAfter(deadline: .now() + 12.0) { [weak self] in
                guard let self, self.isVerifying, self.activationGeneration == gen else { return }
                self.stopCheckingTimer()
                self.isVerifying = false
                SecCoreBridge.shared.wipeSession()
                let msg = "Hết thời gian phản hồi từ máy chủ kích hoạt (12s). Vui lòng thử lại."
                self.errorMessage = msg
                self.gatePhase = .requiresKey
            }

            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                let outcome = SecCoreBridge.shared.activate(licenseKey: trimmed)
                DispatchQueue.main.async {
                    guard let self, self.isVerifying, self.activationGeneration == gen else { return }
                    self.stopCheckingTimer()
                    self.isVerifying = false
                    switch outcome {
                    case .unlocked(let ticket, let summary, let presetStatuses):
                        KeychainLicenseVault.saveLicenseKey(trimmed)
                        self.updatePresetStatuses(presetStatuses)
                        self.currentKey = trimmed
                        self.role = summary.role.isEmpty ? "VIP" : summary.role
                        self.isPermanent = summary.isPermanent
                        self.deviceSlotsText = summary.maxDevices == 0
                            ? "\(summary.usedDevices) / Vô hạn"
                            : "\(summary.usedDevices) / \(summary.maxDevices) máy"

                        if summary.isPermanent {
                            self.expiryDateText = "Vĩnh Viễn"
                            self.exactExpiryDateText = "Vĩnh Viễn (Trọn Đời)"
                            self.remainingCountdownText = "Vĩnh Viễn (Trọn Đời)"
                            self.expirationDate = nil
                            self.secondsRemaining = 999_999_999
                        } else {
                            let expDate = Date(timeIntervalSince1970: TimeInterval(summary.expiryTS))
                            self.expirationDate = expDate
                            self.secondsRemaining = max(0, TimeInterval(summary.remainingSeconds))
                            self.expiryDateText = summary.expiryText
                            let fmt = DateFormatter()
                            fmt.dateFormat = "dd/MM/yyyy 'lúc' HH:mm:ss"
                            self.exactExpiryDateText = fmt.string(from: expDate)
                            self.updateCountdownText()
                        }
                        self.gatePhase = .unlocked(ticket)
                        self.startTimers()

                    case .serverClosed(let msg):
                        self.lockOut(to: .serverClosed(message: msg))

                    case .deviceBanned(let reason, let hwid):
                        self.lockOut(to: .deviceBanned(reason: reason, hwid: hwid))

                    case .forceUpdate(let minV, let latV, let url, let msg):
                        self.lockOut(to: .forceUpdate(minVersion: minV, latestVersion: latV, downloadURL: url, message: msg))

                    case .tampered(let msg):
                        self.lockOut(to: .tampered(message: msg))

                    case .denied(_, let msg):
                        SecCoreBridge.shared.wipeSession()
                        if isSilent {
                            KeychainLicenseVault.deleteLicenseKey()
                        }
                        self.errorMessage = msg
                        self.gatePhase = .requiresKey

                    case .cryptoError(let msg), .networkError(let msg):
                        SecCoreBridge.shared.wipeSession()
                        self.errorMessage = msg
                        self.gatePhase = .requiresKey

                    case .preflightOpen:
                        self.gatePhase = .requiresKey
                    }
                }
            }
        }
    }

    func verifyLiveSessionOnForeground() {
        switch gatePhase {
        case .unlocked:
            performHeartbeat()
        case .connectionError, .serverClosed, .deviceBanned, .forceUpdate:
            bootstrapCheck(force: true)
        case .checking:
            startBootstrapIfNeeded()
        default:
            break
        }
    }

    private func performHeartbeat() {
        DispatchQueue.global(qos: .utility).async {
            let outcome = SecCoreBridge.shared.heartbeat()
            DispatchQueue.main.async {
                switch outcome {
                case .unlocked(let ticket, _, let presetStatuses):
                    self.updatePresetStatuses(presetStatuses)
                    self.gatePhase = .unlocked(ticket)
                case .serverClosed(let msg):
                    self.lockOut(to: .serverClosed(message: msg))
                case .deviceBanned(let reason, let hwid):
                    self.lockOut(to: .deviceBanned(reason: reason, hwid: hwid))
                case .forceUpdate(let minV, let latV, let url, let msg):
                    self.lockOut(to: .forceUpdate(minVersion: minV, latestVersion: latV, downloadURL: url, message: msg))
                case .tampered(let msg):
                    self.lockOut(to: .tampered(message: msg))
                case .cryptoError(let msg):
                    SecCoreBridge.shared.wipeSession()
                    self.stopTimers()
                    self.errorMessage = msg
                    self.gatePhase = .requiresKey
                case .denied(_, let msg):
                    SecCoreBridge.shared.wipeSession()
                    self.stopTimers()
                    self.errorMessage = msg
                    self.gatePhase = .requiresKey
                case .networkError, .preflightOpen:
                    // Keep checking ticket expiry locally while transient network error recovers
                    self.checkExpirationNow()
                }
            }
        }
    }

    func unlinkKey() {
        KeychainLicenseVault.deleteLicenseKey()
        SecCoreBridge.shared.wipeSession()
        DispatchQueue.main.async {
            self.stopTimers()
            self.stopCheckingTimer()
            self.bootstrapGeneration &+= 1
            self.activationGeneration &+= 1
            self.isBootstrapping = false
            self.isVerifying = false
            self.currentKey = ""
            self.expirationDate = nil
            self.remainingCountdownText = ""
            self.errorMessage = nil
            self.gatePhase = .requiresKey
        }
    }

    func checkExpirationNow() {
        guard case .unlocked(let ticket) = gatePhase else { return }
        if !SecCoreBridge.shared.isActiveTicketValid(ticket) {
            SecCoreBridge.shared.wipeSession()
            stopTimers()
            self.errorMessage = "Phiên hoặc Key bản quyền đã hết hạn. Vui lòng xác thực lại."
            self.gatePhase = .requiresKey
            return
        }
        guard !isPermanent, let exp = expirationDate else { return }
        let now = Date()
        if now >= exp {
            SecCoreBridge.shared.wipeSession()
            stopTimers()
            self.errorMessage = "Key của bạn đã hết hạn sử dụng!"
            self.gatePhase = .requiresKey
        } else {
            self.secondsRemaining = exp.timeIntervalSince(now)
            updateCountdownText()
        }
    }

    private func lockOut(to phase: SecurityGatePhase) {
        stopTimers()
        stopCheckingTimer()
        bootstrapGeneration &+= 1
        activationGeneration &+= 1
        isBootstrapping = false
        isVerifying = false
        SecCoreBridge.shared.wipeSession()
        self.gatePhase = phase
    }

    private func startTimers() {
        stopTimers()
        countdownTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.checkExpirationNow()
        }
        heartbeatTimer = Timer.scheduledTimer(withTimeInterval: 90.0, repeats: true) { [weak self] _ in
            self?.performHeartbeat()
        }
    }

    private func stopTimers() {
        countdownTimer?.invalidate()
        countdownTimer = nil
        heartbeatTimer?.invalidate()
        heartbeatTimer = nil
    }

    private func updateCountdownText() {
        guard !isPermanent else {
            remainingCountdownText = "Vĩnh Viễn (Trọn Đời)"
            return
        }
        let total = Int(max(0, secondsRemaining))
        let days = total / 86400
        let hours = (total % 86400) / 3600
        let minutes = (total % 3600) / 60
        let secs = total % 60
        if days > 0 {
            remainingCountdownText = String(format: "%d ngày %02d:%02d:%02d", days, hours, minutes, secs)
        } else if hours > 0 {
            remainingCountdownText = String(format: "%02d giờ %02d phút %02d giây", hours, minutes, secs)
        } else {
            remainingCountdownText = String(format: "%02d phút %02d giây", minutes, secs)
        }
    }
}

struct SecurityCheckingView: View {
    let message: String
    let elapsedSeconds: Int
    var onRetry: (() -> Void)? = nil

    var body: some View {
        ZStack {
            AppPageBackground()
            VStack(spacing: 18) {
                AppLogo(size: 76)
                ProgressView()
                    .tint(AppTheme.accent)
                    .scaleEffect(1.2)
                Text("ĐANG KIỂM TRA BẢO MẬT")
                    .font(.system(size: 13, weight: .heavy, design: .rounded))
                    .tracking(1.3)
                    .foregroundStyle(.white)
                Text(message)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(AppTheme.subduedText)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)

                VStack(spacing: 10) {
                    HStack(spacing: 6) {
                        Image(systemName: "clock")
                            .font(.system(size: 11))
                        Text("Thời gian chờ: \(elapsedSeconds)s / 12s")
                            .font(.system(size: 11.5, weight: .semibold, design: .monospaced))
                    }
                    .foregroundStyle(AppTheme.accentSoft.opacity(0.9))
                    .padding(.horizontal, 12)
                    .padding(.vertical, 5)
                    .background(Color.white.opacity(0.06), in: Capsule())

                    if elapsedSeconds >= 3, let onRetry {
                        Button(action: onRetry) {
                            Label("Thử lại kết nối", systemImage: "arrow.clockwise")
                                .font(.system(size: 12.5, weight: .bold, design: .rounded))
                                .foregroundStyle(.white)
                                .padding(.horizontal, 16)
                                .padding(.vertical, 8)
                                .background(Color.white.opacity(0.12), in: Capsule())
                        }
                        .transition(.opacity)
                    }
                }
                .padding(.top, 4)
            }
        }
    }
}

struct SecurityLockoutView: View {
    enum LockoutMode {
        case connectionError(message: String)
        case serverClosed(message: String)
        case deviceBanned(reason: String, hwid: String)
        case forceUpdate(minVersion: String, latestVersion: String, downloadURL: String, message: String)
        case tampered(message: String)
    }

    let mode: LockoutMode
    let onRetry: () -> Void
    @Environment(\.openURL) private var openURL

    var body: some View {
        ZStack {
            AppPageBackground()
            VStack(spacing: 22) {
                Spacer()
                ZStack {
                    Circle()
                        .fill(accentColor.opacity(0.16))
                        .frame(width: 96, height: 96)
                    Image(systemName: iconName)
                        .font(.system(size: 42, weight: .bold))
                        .foregroundStyle(accentColor)
                }

                Text(titleText)
                    .font(.system(size: 22, weight: .heavy, design: .rounded))
                    .foregroundStyle(.white)
                    .multilineTextAlignment(.center)

                Text(bodyText)
                    .font(.system(size: 13.5, weight: .medium))
                    .foregroundStyle(AppTheme.subduedText)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 28)

                if case .deviceBanned(_, let hwid) = mode, !hwid.isEmpty {
                    Text("HWID: \(hwid)")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.white.opacity(0.75))
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .padding(.horizontal, 28)
                        .textSelection(.enabled)
                }

                if case .forceUpdate(let minV, let latV, let urlStr, _) = mode {
                    VStack(spacing: 10) {
                        Text("Yêu cầu tối thiểu: v\(minV) · Bản mới nhất: v\(latV)")
                            .font(.system(size: 11.5, weight: .bold, design: .monospaced))
                            .foregroundStyle(AppTheme.accentSoft)

                        if let url = URL(string: urlStr), !urlStr.isEmpty {
                            Button {
                                openURL(url)
                            } label: {
                                HStack {
                                    Image(systemName: "arrow.down.circle.fill")
                                    Text("TẢI PHIÊN BẢN MỚI NGAY")
                                }
                                .font(.system(size: 14, weight: .heavy, design: .rounded))
                                .foregroundStyle(.white)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 14)
                                .background(
                                    LinearGradient(colors: [AppTheme.accent, AppTheme.accentDeep], startPoint: .leading, endPoint: .trailing),
                                    in: RoundedRectangle(cornerRadius: 14, style: .continuous)
                                )
                            }
                            .padding(.horizontal, 28)
                        }
                    }
                }

                Button(action: onRetry) {
                    HStack(spacing: 8) {
                        Image(systemName: "arrow.clockwise")
                        Text("Kiểm tra lại kết nối")
                    }
                    .font(.system(size: 13, weight: .bold, design: .rounded))
                    .foregroundStyle(.white)
                    .padding(.horizontal, 22)
                    .padding(.vertical, 11)
                    .background(Color.white.opacity(0.1), in: Capsule())
                }
                Spacer()
            }
        }
    }

    private var iconName: String {
        switch mode {
        case .connectionError: return "wifi.exclamationmark"
        case .serverClosed: return "power.circle.fill"
        case .deviceBanned: return "nosign"
        case .forceUpdate: return "arrow.triangle.2.circlepath.circle.fill"
        case .tampered: return "exclamationmark.shield.fill"
        }
    }

    private var accentColor: Color {
        switch mode {
        case .connectionError: return AppTheme.warning
        case .serverClosed: return AppTheme.warning
        case .deviceBanned: return AppTheme.danger
        case .forceUpdate: return AppTheme.accent
        case .tampered: return AppTheme.danger
        }
    }

    private var titleText: String {
        switch mode {
        case .connectionError: return "Không Thể Kết Nối Máy Chủ"
        case .serverClosed: return "Máy Chủ Đang Tạm Đóng"
        case .deviceBanned: return "Thiết Bị Đã Bị Khóa (Banned)"
        case .forceUpdate: return "Bắt Buộc Cập Nhật Ứng Dụng"
        case .tampered: return "Cảnh Báo Toàn Vẹn Bảo Mật"
        }
    }

    private var bodyText: String {
        switch mode {
        case .connectionError(let message): return message
        case .serverClosed(let message): return message
        case .deviceBanned(let reason, _): return reason
        case .forceUpdate(_, _, _, let message): return message
        case .tampered(let message):
            return message.isEmpty ? "Ứng dụng phát hiện môi trường bất thường hoặc mã nhị phân bị chỉnh sửa." : message
        }
    }
}

struct KeyGatekeeperView: View {
    @ObservedObject var keyAuth = KeyAuthManager.shared
    @State private var inputKey: String = ""
    @State private var showCopiedHWID: Bool = false

    var body: some View {
        ZStack {
            AppPageBackground()
            ScrollView(showsIndicators: false) {
                VStack(spacing: 24) {
                    Spacer(minLength: 28)

                    VStack(spacing: 12) {
                        AppLogo(size: 86)
                            .shadow(color: AppTheme.accent.opacity(0.35), radius: 22, y: 8)
                        Text(AppBrand.name)
                            .font(.system(size: 26, weight: .heavy, design: .rounded))
                            .foregroundStyle(.white)
                        Text("BẢO MẬT ĐA LỚP · XÁC THỰC BẢN QUYỀN V3")
                            .font(.system(size: 10, weight: .heavy, design: .rounded))
                            .tracking(1.6)
                            .foregroundStyle(AppTheme.accentSoft)
                    }

                    VStack(alignment: .leading, spacing: 14) {
                        Text("NHẬP MÃ KEY KÍCH HOẠT")
                            .font(.system(size: 11, weight: .heavy, design: .rounded))
                            .tracking(0.8)
                            .foregroundStyle(AppTheme.subduedText)

                        HStack(spacing: 10) {
                            Image(systemName: "key.fill")
                                .foregroundStyle(AppTheme.accent)
                            TextField("TOBIAIM-XXXX-XXXX-XXXX", text: $inputKey)
                                .textInputAutocapitalization(.characters)
                                .autocorrectionDisabled(true)
                                .font(.system(size: 14, weight: .bold, design: .monospaced))
                                .foregroundStyle(.white)

                            Button {
                                if let pasted = UIPasteboard.general.string {
                                    inputKey = pasted.trimmingCharacters(in: .whitespacesAndNewlines)
                                }
                            } label: {
                                Text("Dán")
                                    .font(.system(size: 11.5, weight: .bold, design: .rounded))
                                    .padding(.horizontal, 10)
                                    .padding(.vertical, 6)
                                    .background(AppTheme.accent.opacity(0.18), in: Capsule())
                                    .foregroundStyle(AppTheme.accentSoft)
                            }
                        }
                        .padding(14)
                        .background(Color.black.opacity(0.28), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                        .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(Color.white.opacity(0.12), lineWidth: 1))

                        if let err = keyAuth.errorMessage {
                            HStack(spacing: 8) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundStyle(AppTheme.danger)
                                Text(err)
                                    .font(.system(size: 12, weight: .semibold))
                                    .foregroundStyle(AppTheme.danger)
                            }
                            .padding(10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(AppTheme.danger.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
                        }

                        Button {
                            keyAuth.activateKey(inputKey, isSilent: false)
                        } label: {
                            HStack(spacing: 8) {
                                if keyAuth.isVerifying {
                                    ProgressView().tint(.white)
                                } else {
                                    Image(systemName: "checkmark.shield.fill")
                                }
                                Text(keyAuth.isVerifying ? "ĐANG MÃ HÓA & XÁC THỰC..." : "KÍCH HOẠT BẢN QUYỀN")
                            }
                            .font(.system(size: 14, weight: .heavy, design: .rounded))
                            .foregroundStyle(.white)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 14)
                            .background(
                                LinearGradient(colors: [AppTheme.accent, AppTheme.accentDeep], startPoint: .leading, endPoint: .trailing),
                                in: RoundedRectangle(cornerRadius: 14, style: .continuous)
                            )
                        }
                        .disabled(keyAuth.isVerifying)

                        if keyAuth.errorMessage != nil {
                            Button {
                                keyAuth.bootstrapCheck(force: true)
                            } label: {
                                Label("Kiểm tra lại kết nối máy chủ", systemImage: "arrow.clockwise")
                                    .font(.system(size: 12, weight: .bold, design: .rounded))
                                    .foregroundStyle(AppTheme.accentSoft)
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 8)
                            }
                            .disabled(keyAuth.isVerifying)
                        }
                    }
                    .padding(18)
                    .background(AppTheme.consoleBackground, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
                    .overlay { AppCardBorder(cornerRadius: 22) }

                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("MÃ THIẾT BỊ (DEVICE FINGERPRINT)")
                                .font(.system(size: 10, weight: .heavy, design: .rounded))
                                .foregroundStyle(AppTheme.subduedText)
                            Spacer()
                            Button {
                                UIPasteboard.general.string = keyAuth.deviceHWID
                                showCopiedHWID = true
                                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { showCopiedHWID = false }
                            } label: {
                                Text(showCopiedHWID ? "Đã chép!" : "Sao chép")
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundStyle(AppTheme.accent)
                            }
                        }
                        Text(keyAuth.deviceHWID)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.white.opacity(0.85))
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    .padding(14)
                    .background(AppTheme.consoleBackground, in: RoundedRectangle(cornerRadius: 16))
                    .overlay { AppCardBorder(cornerRadius: 16) }

                    Spacer(minLength: 20)
                }
                .padding(.horizontal, 20)
            }
        }
        .onAppear {
            if inputKey.isEmpty && !keyAuth.currentKey.isEmpty {
                inputKey = keyAuth.currentKey
            }
        }
    }
}

struct KeyLicenseDetailView: View {
    @ObservedObject var keyAuth = KeyAuthManager.shared
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section("Thông tin bản quyền") {
                    LabeledContent("Mã Key", value: keyAuth.currentKey)
                    LabeledContent("Gói", value: keyAuth.role.uppercased())
                    LabeledContent("Thiết bị", value: keyAuth.deviceSlotsText)
                    LabeledContent("Thời hạn", value: keyAuth.exactExpiryDateText)
                    LabeledContent("Còn lại", value: keyAuth.remainingCountdownText)
                }
                Section("Định danh phần cứng") {
                    Text(keyAuth.deviceHWID)
                        .font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)
                }
                Section {
                    Button(role: .destructive) {
                        keyAuth.unlinkKey()
                        dismiss()
                    } label: {
                        Text("Hủy liên kết Key trên máy này")
                    }
                }
            }
            .navigationTitle("Chi tiết Key V3")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Đóng") { dismiss() }
                }
            }
        }
        .preferredColorScheme(.dark)
    }
}
