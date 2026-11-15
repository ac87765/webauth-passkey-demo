#pragma once

#include "PasskeyTypes.h"
#include <functional>
#include <memory>

namespace sectrade::passkey {

class IPasskeyProvider {
public:
    virtual ~IPasskeyProvider() = default;

    // 返回当前平台原生实现名称 (如 "Windows Hello (webauthn.dll)" / "Apple AuthenticationServices")
    virtual QString platformName() const = 0;

    // 检测当前设备是否支持平台级生物识别/Passkey认证器
    virtual bool isPlatformAuthenticatorAvailable(QString* outDetail = nullptr) const = 0;

    // 异步发起 Passkey 注册 (MakeCredential)
    virtual void makeCredentialAsync(
        const MakeCredentialRequest& request,
        std::function<void(const MakeCredentialResult&)> callback) = 0;

    // 异步发起 Passkey 登录断言 (GetAssertion)
    virtual void getAssertionAsync(
        const GetAssertionRequest& request,
        std::function<void(const GetAssertionResult&)> callback) = 0;

    // 取消当前正在进行的系统生物识别弹窗
    virtual void cancelCurrentOperation() = 0;
};

std::unique_ptr<IPasskeyProvider> createPlatformPasskeyProvider();

} // namespace sectrade::passkey
