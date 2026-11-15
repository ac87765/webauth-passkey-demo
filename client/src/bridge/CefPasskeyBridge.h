#pragma once

#include "../passkey/PasskeyManager.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QObject>
#include <functional>

namespace sectrade::bridge {

/**
 * @brief CEF (Chromium Embedded Framework) <-> Qt C++ 原生 Passkey 桥接适配器
 *
 * 在公司现有的 CEF + Qt + C++ 架构中，前端网页可通过 window.cefQuery 发送 JSON 指令：
 *   window.cefQuery({
 *     request: JSON.stringify({ action: "passkey.login", username: "88001234" }),
 *     onSuccess: (resp) => console.log("Token:", JSON.parse(resp).token),
 *     onFailure: (code, msg) => console.error(msg)
 *   });
 *
 * Browser 主进程的 CefMessageRouterBrowserSide::Handler 只需调用本类的 handleCefRequest()，
 * 即可在 C++ 主进程唤起 Windows Hello / macOS Touch ID，避免 CEF 内核版本老旧或子进程无权限的问题。
 */
class CefPasskeyBridge : public QObject {
    Q_OBJECT
public:
    explicit CefPasskeyBridge(sectrade::passkey::PasskeyManager* manager, QObject* parent = nullptr)
        : QObject(parent), manager_(manager) {}

    void handleCefRequest(
        const QString& requestJson,
        std::function<void(const QString& responseJson)> onSuccess,
        std::function<void(int errorCode, const QString& errorMessage)> onFailure) {

        QJsonObject req = QJsonDocument::fromJson(requestJson.toUtf8()).object();
        QString action = req.value(QStringLiteral("action")).toString();
        QString username = req.value(QStringLiteral("username")).toString();

        if (action == QStringLiteral("passkey.register")) {
            auto connOk = std::make_shared<QMetaObject::Connection>();
            auto connErr = std::make_shared<QMetaObject::Connection>();

            *connOk = connect(manager_, &sectrade::passkey::PasskeyManager::registrationSucceeded,
                              this, [connOk, connErr, onSuccess](const QString& user, const QString& credId) {
                QObject::disconnect(*connOk);
                QObject::disconnect(*connErr);
                QJsonObject resp;
                resp[QStringLiteral("ok")] = true;
                resp[QStringLiteral("username")] = user;
                resp[QStringLiteral("credentialId")] = credId;
                onSuccess(QString::fromUtf8(QJsonDocument(resp).toJson(QJsonDocument::Compact)));
            });

            *connErr = connect(manager_, &sectrade::passkey::PasskeyManager::operationFailed,
                               this, [connOk, connErr, onFailure](const QString& title, const QString& detail) {
                QObject::disconnect(*connOk);
                QObject::disconnect(*connErr);
                onFailure(-1, title + QStringLiteral(": ") + detail);
            });

            manager_->registerPasskey(username, req.value(QStringLiteral("displayName")).toString());
            return;
        }

        if (action == QStringLiteral("passkey.login")) {
            auto connOk = std::make_shared<QMetaObject::Connection>();
            auto connErr = std::make_shared<QMetaObject::Connection>();

            *connOk = connect(manager_, &sectrade::passkey::PasskeyManager::authenticationSucceeded,
                              this, [connOk, connErr, onSuccess](const QString& user, const QString& token) {
                QObject::disconnect(*connOk);
                QObject::disconnect(*connErr);
                QJsonObject resp;
                resp[QStringLiteral("ok")] = true;
                resp[QStringLiteral("username")] = user;
                resp[QStringLiteral("token")] = token;
                onSuccess(QString::fromUtf8(QJsonDocument(resp).toJson(QJsonDocument::Compact)));
            });

            *connErr = connect(manager_, &sectrade::passkey::PasskeyManager::operationFailed,
                               this, [connOk, connErr, onFailure](const QString& title, const QString& detail) {
                QObject::disconnect(*connOk);
                QObject::disconnect(*connErr);
                onFailure(-2, title + QStringLiteral(": ") + detail);
            });

            manager_->loginWithPasskey(username);
            return;
        }

        onFailure(-400, QStringLiteral("未知的 CEF Passkey 指令: ") + action);
    }

private:
    sectrade::passkey::PasskeyManager* manager_ = nullptr;
};

} // namespace sectrade::bridge
