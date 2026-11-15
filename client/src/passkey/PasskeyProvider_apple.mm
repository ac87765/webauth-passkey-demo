#include "IPasskeyProvider.h"

#ifdef Q_OS_APPLE

#import <AuthenticationServices/AuthenticationServices.h>
#import <Foundation/Foundation.h>
#include <TargetConditionals.h>

#if TARGET_OS_IPHONE
#import <UIKit/UIKit.h>
#else
#import <AppKit/AppKit.h>
#endif

#include <QCoreApplication>
#include <QMetaObject>

namespace {

static NSData* toNSData(const QByteArray& bytes) {
    return [NSData dataWithBytes:bytes.constData() length:static_cast<NSUInteger>(bytes.size())];
}

static QByteArray toQByteArray(NSData* data) {
    if (!data || data.length == 0) {
        return {};
    }
    return QByteArray(reinterpret_cast<const char*>(data.bytes), static_cast<int>(data.length));
}

} // namespace

// Objective-C 委托桥接对象：接收系统 Touch ID / Face ID / iCloud 钥匙串回调并绑定宿主窗口
@interface SecTradePasskeyAppleDelegate : NSObject <
    ASAuthorizationControllerDelegate,
    ASAuthorizationControllerPresentationContextProviding>

@property (nonatomic, assign) quintptr targetWindowHandle;
@property (nonatomic, copy) void (^onMakeCredentialComplete)(const sectrade::passkey::MakeCredentialResult&);
@property (nonatomic, copy) void (^onGetAssertionComplete)(const sectrade::passkey::GetAssertionResult&);

@end

@implementation SecTradePasskeyAppleDelegate

- (ASPresentationAnchor)presentationAnchorForAuthorizationController:(ASAuthorizationController*)controller {
    (void)controller;
#if TARGET_OS_IPHONE
    if (self.targetWindowHandle != 0) {
        UIView* view = (__bridge UIView*)reinterpret_cast<void*>(self.targetWindowHandle);
        if (view.window) {
            return view.window;
        }
    }
    for (UIScene* scene in UIApplication.sharedApplication.connectedScenes) {
        if ([scene isKindOfClass:[UIWindowScene class]]) {
            UIWindowScene* windowScene = (UIWindowScene*)scene;
            for (UIWindow* win in windowScene.windows) {
                if (win.isKeyWindow) {
                    return win;
                }
            }
        }
    }
    return [[UIWindow alloc] init];
#else
    if (self.targetWindowHandle != 0) {
        NSView* nsView = (__bridge NSView*)reinterpret_cast<void*>(self.targetWindowHandle);
        if (nsView && nsView.window) {
            return nsView.window;
        }
    }
    if (NSApplication.sharedApplication.keyWindow) {
        return NSApplication.sharedApplication.keyWindow;
    }
    if (NSApplication.sharedApplication.windows.count > 0) {
        return NSApplication.sharedApplication.windows.firstObject;
    }
    return [[NSWindow alloc] init];
#endif
}

- (void)authorizationController:(ASAuthorizationController*)controller
    didCompleteWithAuthorization:(ASAuthorization*)authorization API_AVAILABLE(macos(12.0), ios(15.0)) {
    (void)controller;

    if ([authorization.credential isKindOfClass:[ASAuthorizationPlatformPublicKeyCredentialRegistration class]]) {
        auto* regCred = (ASAuthorizationPlatformPublicKeyCredentialRegistration*)authorization.credential;
        sectrade::passkey::MakeCredentialResult res;
        res.success = true;
        res.credentialIdBase64Url = sectrade::passkey::toBase64Url(toQByteArray(regCred.credentialID));
        res.clientDataJson = toQByteArray(regCred.rawClientDataJSON);
        res.attestationObject = toQByteArray(regCred.rawAttestationObject);

        if (self.onMakeCredentialComplete) {
            self.onMakeCredentialComplete(res);
        }
        return;
    }

    if ([authorization.credential isKindOfClass:[ASAuthorizationPlatformPublicKeyCredentialAssertion class]]) {
        auto* assertCred = (ASAuthorizationPlatformPublicKeyCredentialAssertion*)authorization.credential;
        sectrade::passkey::GetAssertionResult res;
        res.success = true;
        res.credentialIdBase64Url = sectrade::passkey::toBase64Url(toQByteArray(assertCred.credentialID));
        res.clientDataJson = toQByteArray(assertCred.rawClientDataJSON);
        res.authenticatorData = toQByteArray(assertCred.rawAuthenticatorData);
        res.signature = toQByteArray(assertCred.signature);
        res.userHandle = toQByteArray(assertCred.userID);

        if (self.onGetAssertionComplete) {
            self.onGetAssertionComplete(res);
        }
        return;
    }
}

- (void)authorizationController:(ASAuthorizationController*)controller
           didCompleteWithError:(NSError*)error {
    (void)controller;
    bool isCancelled = (error.code == ASAuthorizationErrorCanceled);
    QString errMsg = QString::fromNSString(error.localizedDescription);

    if (self.onMakeCredentialComplete) {
        sectrade::passkey::MakeCredentialResult res;
        res.success = false;
        res.cancelled = isCancelled;
        res.nativeErrorCode = static_cast<qint64>(error.code);
        res.errorMessage = isCancelled
            ? QStringLiteral("用户取消了 Touch ID / Face ID 注册")
            : QStringLiteral("Apple Passkey 注册失败 (请检查 Associated Domains 与 AASA 配置): %1").arg(errMsg);
        self.onMakeCredentialComplete(res);
    }

    if (self.onGetAssertionComplete) {
        sectrade::passkey::GetAssertionResult res;
        res.success = false;
        res.cancelled = isCancelled;
        res.nativeErrorCode = static_cast<qint64>(error.code);
        res.errorMessage = isCancelled
            ? QStringLiteral("用户取消了 Touch ID / Face ID 登录")
            : QStringLiteral("Apple Passkey 登录失败: %1").arg(errMsg);
        self.onGetAssertionComplete(res);
    }
}

@end

namespace sectrade::passkey {

class PasskeyProviderApple final : public IPasskeyProvider {
public:
    QString platformName() const override {
#if TARGET_OS_IPHONE
        return QStringLiteral("iOS AuthenticationServices (Face ID / Touch ID)");
#else
        return QStringLiteral("macOS AuthenticationServices (Touch ID / iCloud 钥匙串)");
#endif
    }

    bool isPlatformAuthenticatorAvailable(QString* outDetail) const override {
        if (@available(macOS 12.0, iOS 16.0, *)) {
            if (outDetail) {
                *outDetail = QStringLiteral("Apple Passkey 原生框架已就绪 (需配置 Associated Domains)");
            }
            return true;
        }
        if (outDetail) {
            *outDetail = QStringLiteral("系统版本过低，需 macOS 12.0+ 或 iOS 16.0+");
        }
        return false;
    }

    void makeCredentialAsync(
        const MakeCredentialRequest& request,
        std::function<void(const MakeCredentialResult&)> callback) override {

        if (@available(macOS 12.0, iOS 15.0, *)) {
            NSString* nsRpId = request.rpId.toNSString();
            auto* provider = [[ASAuthorizationPlatformPublicKeyCredentialProvider alloc]
                initWithRelyingPartyIdentifier:nsRpId];

            auto* regReq = [provider createCredentialRegistrationRequestWithClientDataHash:toNSData(request.challenge)
                                                                                      name:request.userName.toNSString()
                                                                                    userID:toNSData(request.userId)];

            activeDelegate_ = [[SecTradePasskeyAppleDelegate alloc] init];
            activeDelegate_.targetWindowHandle = request.nativeWindowHandle;
            activeDelegate_.onMakeCredentialComplete = ^(const MakeCredentialResult& result) {
                QMetaObject::invokeMethod(
                    QCoreApplication::instance(),
                    [callback, result]() { callback(result); },
                    Qt::QueuedConnection);
            };

            activeController_ = [[ASAuthorizationController alloc]
                initWithAuthorizationRequests:@[ regReq ]];
            activeController_.delegate = activeDelegate_;
            activeController_.presentationContextProvider = activeDelegate_;
            [activeController_ performRequests];
        } else {
            MakeCredentialResult res;
            res.errorMessage = QStringLiteral("当前 macOS/iOS 版本不支持 Passkey API");
            callback(res);
        }
    }

    void getAssertionAsync(
        const GetAssertionRequest& request,
        std::function<void(const GetAssertionResult&)> callback) override {

        if (@available(macOS 12.0, iOS 15.0, *)) {
            NSString* nsRpId = request.rpId.toNSString();
            auto* provider = [[ASAuthorizationPlatformPublicKeyCredentialProvider alloc]
                initWithRelyingPartyIdentifier:nsRpId];

            auto* assertReq = [provider createCredentialAssertionRequestWithClientDataHash:toNSData(request.challenge)];

            if (!request.allowCredentials.isEmpty()) {
                NSMutableArray<ASAuthorizationPlatformPublicKeyCredentialDescriptor*>* allowed =
                    [NSMutableArray array];
                for (const auto& desc : request.allowCredentials) {
                    [allowed addObject:[[ASAuthorizationPlatformPublicKeyCredentialDescriptor alloc]
                                           initWithCredentialID:toNSData(desc.id)]];
                }
                assertReq.allowedCredentials = allowed;
            }

            activeDelegate_ = [[SecTradePasskeyAppleDelegate alloc] init];
            activeDelegate_.targetWindowHandle = request.nativeWindowHandle;
            activeDelegate_.onGetAssertionComplete = ^(const GetAssertionResult& result) {
                QMetaObject::invokeMethod(
                    QCoreApplication::instance(),
                    [callback, result]() { callback(result); },
                    Qt::QueuedConnection);
            };

            activeController_ = [[ASAuthorizationController alloc]
                initWithAuthorizationRequests:@[ assertReq ]];
            activeController_.delegate = activeDelegate_;
            activeController_.presentationContextProvider = activeDelegate_;
            [activeController_ performRequests];
        } else {
            GetAssertionResult res;
            res.errorMessage = QStringLiteral("当前 macOS/iOS 版本不支持 Passkey API");
            callback(res);
        }
    }

    void cancelCurrentOperation() override {
        if (@available(macOS 12.0, iOS 15.0, *)) {
            if (activeController_) {
                [activeController_ cancel];
            }
        }
    }

private:
    SecTradePasskeyAppleDelegate* activeDelegate_ = nil;
    ASAuthorizationController* activeController_ = nil;
};

std::unique_ptr<IPasskeyProvider> createPlatformPasskeyProvider() {
    return std::make_unique<PasskeyProviderApple>();
}

} // namespace sectrade::passkey

#endif // Q_OS_APPLE
