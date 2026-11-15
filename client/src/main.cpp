#include "bridge/CefPasskeyBridge.h"
#include "passkey/PasskeyManager.h"

#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>

int main(int argc, char* argv[]) {
    QGuiApplication app(argc, argv);
    app.setOrganizationName(QStringLiteral("SecTrade"));
    app.setApplicationName(QStringLiteral("SecTradePasskeyDemo"));

    // 使用 Basic 样式以便 QML 自定义暗黑证券终端风格控件无警告渲染
    QQuickStyle::setStyle(QStringLiteral("Basic"));

    sectrade::passkey::PasskeyManager passkeyManager;
    sectrade::bridge::CefPasskeyBridge cefBridge(&passkeyManager);

    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty(QStringLiteral("passkeyManager"), &passkeyManager);

    const QUrl url(QStringLiteral("qrc:/qml/Main.qml"));
    QObject::connect(
        &engine,
        &QQmlApplicationEngine::objectCreated,
        &app,
        [url](QObject* obj, const QUrl& objUrl) {
            if (!obj && url == objUrl) {
                QCoreApplication::exit(-1);
            }
        },
        Qt::QueuedConnection);

    engine.load(url);
    return app.exec();
}
