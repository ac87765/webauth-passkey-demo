#pragma once

#include "IPasskeyProvider.h"
#include <QNetworkAccessManager>
#include <QObject>
#include <QVariantList>
#include <memory>

namespace sectrade::passkey {

class PasskeyManager : public QObject {
    Q_OBJECT

    Q_PROPERTY(QString serverUrl READ serverUrl WRITE setServerUrl NOTIFY serverUrlChanged)
    Q_PROPERTY(QString rpId READ rpId WRITE setRpId NOTIFY rpIdChanged)
    Q_PROPERTY(QString platformName READ platformName CONSTANT)
    Q_PROPERTY(bool hardwareAvailable READ hardwareAvailable CONSTANT)
    Q_PROPERTY(QString hardwareDetail READ hardwareDetail CONSTANT)
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
    Q_PROPERTY(QString statusMessage READ statusMessage NOTIFY statusMessageChanged)
    Q_PROPERTY(bool serverOnline READ serverOnline NOTIFY serverOnlineChanged)
    Q_PROPERTY(QString loggedInUser READ loggedInUser NOTIFY authStateChanged)
    Q_PROPERTY(QString sessionToken READ sessionToken NOTIFY authStateChanged)
    Q_PROPERTY(QString protocolLog READ protocolLog NOTIFY protocolLogChanged)
    Q_PROPERTY(QVariantList registeredCredentials READ registeredCredentials NOTIFY registeredCredentialsChanged)

public:
    explicit PasskeyManager(QObject* parent = nullptr);
    ~PasskeyManager() override = default;

    QString serverUrl() const { return serverUrl_; }
    void setServerUrl(const QString& url);

    QString rpId() const { return rpId_; }
    void setRpId(const QString& id);

    QString platformName() const;
    bool hardwareAvailable() const { return hardwareAvailable_; }
    QString hardwareDetail() const { return hardwareDetail_; }
    bool busy() const { return busy_; }
    QString statusMessage() const { return statusMessage_; }
    bool serverOnline() const { return serverOnline_; }
    QString loggedInUser() const { return loggedInUser_; }
    QString sessionToken() const { return sessionToken_; }
    QString protocolLog() const { return protocolLog_; }
    QVariantList registeredCredentials() const { return registeredCredentials_; }

    // QML & CEF Bridge 可调用的核心方法
    Q_INVOKABLE void checkServerHealth();
    Q_INVOKABLE void refreshRegisteredUsers();
    Q_INVOKABLE void registerPasskey(const QString& username, const QString& displayName = QString());
    Q_INVOKABLE void loginWithPasskey(const QString& username = QString());
    Q_INVOKABLE void deleteUser(const QString& username);
    Q_INVOKABLE void logout();
    Q_INVOKABLE void cancelOperation();
    Q_INVOKABLE void clearLogs();

signals:
    void serverUrlChanged();
    void rpIdChanged();
    void busyChanged();
    void statusMessageChanged();
    void serverOnlineChanged();
    void authStateChanged();
    void protocolLogChanged();
    void registeredCredentialsChanged();

    void registrationSucceeded(const QString& username, const QString& credentialId);
    void authenticationSucceeded(const QString& username, const QString& token);
    void operationFailed(const QString& title, const QString& detail);

private:
    void setBusy(bool b);
    void setStatus(const QString& msg);
    void appendLog(const QString& tag, const QString& message);
    quintptr currentWindowHandle() const;

    std::unique_ptr<IPasskeyProvider> provider_;
    QNetworkAccessManager net_;

    QString serverUrl_ = QStringLiteral("https://120.79.245.99/passkey-demo");
    QString rpId_ = QStringLiteral("myjustfun.fun");
    bool hardwareAvailable_ = false;
    QString hardwareDetail_;
    bool busy_ = false;
    QString statusMessage_ = QStringLiteral("就绪：请先确保 Passkey Server 已启动");
    bool serverOnline_ = false;
    QString loggedInUser_;
    QString sessionToken_;
    QString protocolLog_;
    QVariantList registeredCredentials_;
};

} // namespace sectrade::passkey
