#pragma once

#include <QByteArray>
#include <QJsonObject>
#include <QList>
#include <QString>

namespace sectrade::passkey {

// Base64URL 编解码工具函数 (遵循 RFC 4648 Section 5，无填充 '=')
inline QString toBase64Url(const QByteArray& data) {
    return QString::fromLatin1(
        data.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

inline QByteArray fromBase64Url(const QString& b64url) {
    return QByteArray::fromBase64(
        b64url.toLatin1(),
        QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
}

struct PublicKeyCredentialDescriptorDto {
    QByteArray id;
    QString type = QStringLiteral("public-key");
};

// 传给系统原生 API (Windows Hello / Apple AuthenticationServices) 的注册参数
struct MakeCredentialRequest {
    QString rpId;
    QString rpName;
    QByteArray userId;
    QString userName;
    QString userDisplayName;
    QByteArray challenge;
    QString challengeBase64Url;
    QList<PublicKeyCredentialDescriptorDto> excludeCredentials;
    quint32 timeoutMs = 60000;
    quintptr nativeWindowHandle = 0; // Windows: HWND, macOS: NSView*/NSWindow*, iOS: UIView*/UIWindow*
};

// 系统原生 API 返回的注册结果 (可直接序列化为标准 W3C WebAuthn JSON)
struct MakeCredentialResult {
    bool success = false;
    bool cancelled = false;
    QString errorMessage;
    qint64 nativeErrorCode = 0;

    QString credentialIdBase64Url;
    QByteArray clientDataJson;
    QByteArray attestationObject;

    QJsonObject toWebAuthnJson() const {
        QJsonObject responseObj;
        responseObj[QStringLiteral("clientDataJSON")] = toBase64Url(clientDataJson);
        responseObj[QStringLiteral("attestationObject")] = toBase64Url(attestationObject);

        QJsonObject root;
        root[QStringLiteral("id")] = credentialIdBase64Url;
        root[QStringLiteral("rawId")] = credentialIdBase64Url;
        root[QStringLiteral("type")] = QStringLiteral("public-key");
        root[QStringLiteral("response")] = responseObj;
        return root;
    }
};

// 传给系统原生 API 的登录签名参数
struct GetAssertionRequest {
    QString rpId;
    QByteArray challenge;
    QString challengeBase64Url;
    QList<PublicKeyCredentialDescriptorDto> allowCredentials;
    quint32 timeoutMs = 60000;
    quintptr nativeWindowHandle = 0;
};

// 系统原生 API 返回的登录断言结果 (可直接序列化为标准 W3C WebAuthn JSON)
struct GetAssertionResult {
    bool success = false;
    bool cancelled = false;
    QString errorMessage;
    qint64 nativeErrorCode = 0;

    QString credentialIdBase64Url;
    QByteArray clientDataJson;
    QByteArray authenticatorData;
    QByteArray signature;
    QByteArray userHandle;

    QJsonObject toWebAuthnJson() const {
        QJsonObject responseObj;
        responseObj[QStringLiteral("clientDataJSON")] = toBase64Url(clientDataJson);
        responseObj[QStringLiteral("authenticatorData")] = toBase64Url(authenticatorData);
        responseObj[QStringLiteral("signature")] = toBase64Url(signature);
        if (!userHandle.isEmpty()) {
            responseObj[QStringLiteral("userHandle")] = toBase64Url(userHandle);
        }

        QJsonObject root;
        root[QStringLiteral("id")] = credentialIdBase64Url;
        root[QStringLiteral("rawId")] = credentialIdBase64Url;
        root[QStringLiteral("type")] = QStringLiteral("public-key");
        root[QStringLiteral("response")] = responseObj;
        return root;
    }
};

} // namespace sectrade::passkey
