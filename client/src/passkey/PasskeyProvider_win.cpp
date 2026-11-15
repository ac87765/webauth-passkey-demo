#include "IPasskeyProvider.h"

#ifdef Q_OS_WIN

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <webauthn.h>

#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMetaObject>
#include <mutex>
#include <thread>
#include <vector>

namespace sectrade::passkey {

namespace {

// 动态加载 webauthn.dll 函数指针，兼容 MSVC 与 MinGW 编译环境，无需静态链接 webauthn.lib
struct WebAuthnDllApi {
    HMODULE hModule = nullptr;
    decltype(&WebAuthNGetApiVersionNumber) pfnGetApiVersionNumber = nullptr;
    decltype(&WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable) pfnIsUvpaa = nullptr;
    decltype(&WebAuthNAuthenticatorMakeCredential) pfnMakeCredential = nullptr;
    decltype(&WebAuthNAuthenticatorGetAssertion) pfnGetAssertion = nullptr;
    decltype(&WebAuthNFreeCredentialAttestation) pfnFreeAttestation = nullptr;
    decltype(&WebAuthNFreeAssertion) pfnFreeAssertion = nullptr;
    decltype(&WebAuthNGetCancellationId) pfnGetCancellationId = nullptr;
    decltype(&WebAuthNCancelCurrentOperation) pfnCancelOperation = nullptr;
    decltype(&WebAuthNGetErrorName) pfnGetErrorName = nullptr;

    WebAuthnDllApi() {
        hModule = LoadLibraryW(L"webauthn.dll");
        if (!hModule) {
            return;
        }
        pfnGetApiVersionNumber = reinterpret_cast<decltype(pfnGetApiVersionNumber)>(
            GetProcAddress(hModule, "WebAuthNGetApiVersionNumber"));
        pfnIsUvpaa = reinterpret_cast<decltype(pfnIsUvpaa)>(
            GetProcAddress(hModule, "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable"));
        pfnMakeCredential = reinterpret_cast<decltype(pfnMakeCredential)>(
            GetProcAddress(hModule, "WebAuthNAuthenticatorMakeCredential"));
        pfnGetAssertion = reinterpret_cast<decltype(pfnGetAssertion)>(
            GetProcAddress(hModule, "WebAuthNAuthenticatorGetAssertion"));
        pfnFreeAttestation = reinterpret_cast<decltype(pfnFreeAttestation)>(
            GetProcAddress(hModule, "WebAuthNFreeCredentialAttestation"));
        pfnFreeAssertion = reinterpret_cast<decltype(pfnFreeAssertion)>(
            GetProcAddress(hModule, "WebAuthNFreeAssertion"));
        pfnGetCancellationId = reinterpret_cast<decltype(pfnGetCancellationId)>(
            GetProcAddress(hModule, "WebAuthNGetCancellationId"));
        pfnCancelOperation = reinterpret_cast<decltype(pfnCancelOperation)>(
            GetProcAddress(hModule, "WebAuthNCancelCurrentOperation"));
        pfnGetErrorName = reinterpret_cast<decltype(pfnGetErrorName)>(
            GetProcAddress(hModule, "WebAuthNGetErrorName"));
    }

    bool isLoaded() const {
        return hModule != nullptr && pfnMakeCredential != nullptr && pfnGetAssertion != nullptr;
    }
};

const WebAuthnDllApi& dll() {
    static WebAuthnDllApi instance;
    return instance;
}

QByteArray buildClientDataJson(const QString& type, const QString& challengeB64Url, const QString& rpId) {
    QJsonObject obj;
    obj[QStringLiteral("type")] = type;
    obj[QStringLiteral("challenge")] = challengeB64Url;
    obj[QStringLiteral("origin")] = QStringLiteral("https://") + rpId;
    obj[QStringLiteral("crossOrigin")] = false;
    return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

QString formatHrError(HRESULT hr) {
    QString errName;
    if (dll().pfnGetErrorName) {
        PCWSTR wName = dll().pfnGetErrorName(hr);
        if (wName) {
            errName = QString::fromWCharArray(wName);
        }
    }
    return QStringLiteral("HRESULT 0x%1 (%2)")
        .arg(static_cast<quint32>(hr), 8, 16, QLatin1Char('0'))
        .arg(errName.isEmpty() ? QStringLiteral("Unknown") : errName);
}

bool isCancelledHr(HRESULT hr) {
    constexpr HRESULT kNteUserCancelled = static_cast<HRESULT>(0x80090036L);
    return hr == kNteUserCancelled || hr == HRESULT_FROM_WIN32(ERROR_CANCELLED);
}

HWND resolveTargetHwnd(quintptr handle) {
    if (handle != 0) {
        return reinterpret_cast<HWND>(handle);
    }
    HWND fg = GetForegroundWindow();
    return fg ? fg : GetDesktopWindow();
}

} // namespace

class PasskeyProviderWin final : public IPasskeyProvider {
public:
    QString platformName() const override {
        if (!dll().isLoaded()) {
            return QStringLiteral("Windows (webauthn.dll 未加载)");
        }
        DWORD ver = dll().pfnGetApiVersionNumber ? dll().pfnGetApiVersionNumber() : 0;
        return QStringLiteral("Windows Hello 原生 API (webauthn.dll v%1)").arg(ver);
    }

    bool isPlatformAuthenticatorAvailable(QString* outDetail) const override {
        if (!dll().isLoaded() || !dll().pfnIsUvpaa) {
            if (outDetail) {
                *outDetail = QStringLiteral("系统不支持 webauthn.dll (需 Windows 10 1903+)");
            }
            return false;
        }
        BOOL available = FALSE;
        HRESULT hr = dll().pfnIsUvpaa(&available);
        if (SUCCEEDED(hr) && available) {
            if (outDetail) {
                *outDetail = QStringLiteral("Windows Hello 平台认证器已就绪 (支持 PIN/指纹/人脸/跨设备扫码)");
            }
            return true;
        }
        if (outDetail) {
            *outDetail = QStringLiteral("Windows Hello 未启用或未配置 PIN (%1，仍可使用跨设备手机/安全密钥)").arg(formatHrError(hr));
        }
        return false;
    }

    void makeCredentialAsync(
        const MakeCredentialRequest& request,
        std::function<void(const MakeCredentialResult&)> callback) override {

        GUID cancellationId{};
        if (dll().pfnGetCancellationId) {
            dll().pfnGetCancellationId(&cancellationId);
            std::lock_guard<std::mutex> lock(mutex_);
            activeCancellationId_ = cancellationId;
            hasActiveOperation_ = true;
        }

        std::thread([this, request, callback, cancellationId]() {
            MakeCredentialResult result = executeMakeCredentialSync(request, cancellationId);
            {
                std::lock_guard<std::mutex> lock(mutex_);
                hasActiveOperation_ = false;
            }
            QMetaObject::invokeMethod(
                QCoreApplication::instance(),
                [callback, result]() { callback(result); },
                Qt::QueuedConnection);
        }).detach();
    }

    void getAssertionAsync(
        const GetAssertionRequest& request,
        std::function<void(const GetAssertionResult&)> callback) override {

        GUID cancellationId{};
        if (dll().pfnGetCancellationId) {
            dll().pfnGetCancellationId(&cancellationId);
            std::lock_guard<std::mutex> lock(mutex_);
            activeCancellationId_ = cancellationId;
            hasActiveOperation_ = true;
        }

        std::thread([this, request, callback, cancellationId]() {
            GetAssertionResult result = executeGetAssertionSync(request, cancellationId);
            {
                std::lock_guard<std::mutex> lock(mutex_);
                hasActiveOperation_ = false;
            }
            QMetaObject::invokeMethod(
                QCoreApplication::instance(),
                [callback, result]() { callback(result); },
                Qt::QueuedConnection);
        }).detach();
    }

    void cancelCurrentOperation() override {
        std::lock_guard<std::mutex> lock(mutex_);
        if (hasActiveOperation_ && dll().pfnCancelOperation) {
            dll().pfnCancelOperation(&activeCancellationId_);
            hasActiveOperation_ = false;
        }
    }

private:
    MakeCredentialResult executeMakeCredentialSync(
        const MakeCredentialRequest& req,
        GUID cancellationId) {

        MakeCredentialResult res;
        if (!dll().isLoaded()) {
            res.errorMessage = QStringLiteral("加载系统 webauthn.dll 失败");
            return res;
        }

        std::wstring wRpId = req.rpId.toStdWString();
        std::wstring wRpName = req.rpName.toStdWString();
        WEBAUTHN_RP_ENTITY_INFORMATION rpInfo{};
        rpInfo.dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
        rpInfo.pwszId = wRpId.c_str();
        rpInfo.pwszName = wRpName.c_str();
        rpInfo.pwszIcon = nullptr;

        QByteArray userIdBytes = req.userId;
        std::wstring wUserName = req.userName.toStdWString();
        std::wstring wDisplayName = req.userDisplayName.toStdWString();
        WEBAUTHN_USER_ENTITY_INFORMATION userInfo{};
        userInfo.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
        userInfo.cbId = static_cast<DWORD>(userIdBytes.size());
        userInfo.pbId = reinterpret_cast<PBYTE>(userIdBytes.data());
        userInfo.pwszName = wUserName.c_str();
        userInfo.pwszIcon = nullptr;
        userInfo.pwszDisplayName = wDisplayName.c_str();

        // 主流算法: ES256 (-7) 与 RS256 (-257)
        WEBAUTHN_COSE_CREDENTIAL_PARAMETER coseParams[2]{};
        coseParams[0].dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION;
        coseParams[0].pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
        coseParams[0].lAlg = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256;

        coseParams[1].dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION;
        coseParams[1].pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
        coseParams[1].lAlg = WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA256;

        WEBAUTHN_COSE_CREDENTIAL_PARAMETERS pubKeyCredParams{};
        pubKeyCredParams.cCredentialParameters = 2;
        pubKeyCredParams.pCredentialParameters = coseParams;

        QByteArray clientDataJson = buildClientDataJson(
            QStringLiteral("webauthn.create"), req.challengeBase64Url, req.rpId);

        WEBAUTHN_CLIENT_DATA clientData{};
        clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
        clientData.cbClientDataJSON = static_cast<DWORD>(clientDataJson.size());
        clientData.pbClientDataJSON = reinterpret_cast<PBYTE>(clientDataJson.data());
        clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

        // 组装排除的已有凭证列表 (防止同一设备重复注册)
        std::vector<QByteArray> excludeIdBuffers;
        std::vector<WEBAUTHN_CREDENTIAL> excludeCreds;
        for (const auto& exc : req.excludeCredentials) {
            excludeIdBuffers.push_back(exc.id);
        }
        for (auto& buf : excludeIdBuffers) {
            WEBAUTHN_CREDENTIAL cred{};
            cred.dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
            cred.cbId = static_cast<DWORD>(buf.size());
            cred.pbId = reinterpret_cast<PBYTE>(buf.data());
            cred.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
            excludeCreds.push_back(cred);
        }

        WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS options{};
        options.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_3;
        options.dwTimeoutMilliseconds = req.timeoutMs;
        if (!excludeCreds.empty()) {
            options.CredentialList.cCredentials = static_cast<DWORD>(excludeCreds.size());
            options.CredentialList.pCredentials = excludeCreds.data();
        }
        options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY;
        options.bRequireResidentKey = FALSE;
        options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED;
        options.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;
        options.pCancellationId = &cancellationId;

        HWND hWnd = resolveTargetHwnd(req.nativeWindowHandle);
        PWEBAUTHN_CREDENTIAL_ATTESTATION pAttestation = nullptr;

        HRESULT hr = dll().pfnMakeCredential(
            hWnd,
            &rpInfo,
            &userInfo,
            &pubKeyCredParams,
            &clientData,
            &options,
            &pAttestation);

        if (FAILED(hr) || !pAttestation) {
            res.nativeErrorCode = static_cast<qint64>(hr);
            res.cancelled = isCancelledHr(hr);
            res.errorMessage = res.cancelled
                ? QStringLiteral("用户取消了 Windows Hello 注册验证")
                : QStringLiteral("Windows Hello 注册失败: %1").arg(formatHrError(hr));
            return res;
        }

        QByteArray credId(
            reinterpret_cast<const char*>(pAttestation->pbCredentialId),
            static_cast<int>(pAttestation->cbCredentialId));
        QByteArray attObj(
            reinterpret_cast<const char*>(pAttestation->pbAttestationObject),
            static_cast<int>(pAttestation->cbAttestationObject));

        dll().pfnFreeAttestation(pAttestation);

        res.success = true;
        res.credentialIdBase64Url = toBase64Url(credId);
        res.clientDataJson = clientDataJson;
        res.attestationObject = attObj;
        return res;
    }

    GetAssertionResult executeGetAssertionSync(
        const GetAssertionRequest& req,
        GUID cancellationId) {

        GetAssertionResult res;
        if (!dll().isLoaded()) {
            res.errorMessage = QStringLiteral("加载系统 webauthn.dll 失败");
            return res;
        }

        std::wstring wRpId = req.rpId.toStdWString();
        QByteArray clientDataJson = buildClientDataJson(
            QStringLiteral("webauthn.get"), req.challengeBase64Url, req.rpId);

        WEBAUTHN_CLIENT_DATA clientData{};
        clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
        clientData.cbClientDataJSON = static_cast<DWORD>(clientDataJson.size());
        clientData.pbClientDataJSON = reinterpret_cast<PBYTE>(clientDataJson.data());
        clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

        std::vector<QByteArray> allowIdBuffers;
        std::vector<WEBAUTHN_CREDENTIAL> allowCreds;
        for (const auto& allow : req.allowCredentials) {
            allowIdBuffers.push_back(allow.id);
        }
        for (auto& buf : allowIdBuffers) {
            WEBAUTHN_CREDENTIAL cred{};
            cred.dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
            cred.cbId = static_cast<DWORD>(buf.size());
            cred.pbId = reinterpret_cast<PBYTE>(buf.data());
            cred.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
            allowCreds.push_back(cred);
        }

        WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS options{};
        options.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_4;
        options.dwTimeoutMilliseconds = req.timeoutMs;
        if (!allowCreds.empty()) {
            options.CredentialList.cCredentials = static_cast<DWORD>(allowCreds.size());
            options.CredentialList.pCredentials = allowCreds.data();
        }
        options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY;
        options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED;
        options.pCancellationId = &cancellationId;

        HWND hWnd = resolveTargetHwnd(req.nativeWindowHandle);
        PWEBAUTHN_ASSERTION pAssertion = nullptr;

        HRESULT hr = dll().pfnGetAssertion(
            hWnd,
            wRpId.c_str(),
            &clientData,
            &options,
            &pAssertion);

        if (FAILED(hr) || !pAssertion) {
            res.nativeErrorCode = static_cast<qint64>(hr);
            res.cancelled = isCancelledHr(hr);
            res.errorMessage = res.cancelled
                ? QStringLiteral("用户取消了 Windows Hello 登录验证")
                : QStringLiteral("Windows Hello 登录验证失败: %1").arg(formatHrError(hr));
            return res;
        }

        QByteArray credId(
            reinterpret_cast<const char*>(pAssertion->Credential.pbId),
            static_cast<int>(pAssertion->Credential.cbId));
        QByteArray authData(
            reinterpret_cast<const char*>(pAssertion->pbAuthenticatorData),
            static_cast<int>(pAssertion->cbAuthenticatorData));
        QByteArray sig(
            reinterpret_cast<const char*>(pAssertion->pbSignature),
            static_cast<int>(pAssertion->cbSignature));
        QByteArray userHandle;
        if (pAssertion->pbUserId && pAssertion->cbUserId > 0) {
            userHandle = QByteArray(
                reinterpret_cast<const char*>(pAssertion->pbUserId),
                static_cast<int>(pAssertion->cbUserId));
        }

        dll().pfnFreeAssertion(pAssertion);

        res.success = true;
        res.credentialIdBase64Url = toBase64Url(credId);
        res.clientDataJson = clientDataJson;
        res.authenticatorData = authData;
        res.signature = sig;
        res.userHandle = userHandle;
        return res;
    }

    std::mutex mutex_;
    GUID activeCancellationId_{};
    bool hasActiveOperation_ = false;
};

std::unique_ptr<IPasskeyProvider> createPlatformPasskeyProvider() {
    return std::make_unique<PasskeyProviderWin>();
}

} // namespace sectrade::passkey

#endif // Q_OS_WIN
