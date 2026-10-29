import Foundation
import Capacitor
import LocalAuthentication

@objc(NativeSecurityPlugin)
public class NativeSecurityPlugin: CAPPlugin, CAPBridgedPlugin {
    public let identifier = "NativeSecurityPlugin"
    public let jsName = "NativeSecurity"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "authenticateWithBiometrics", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "enableScreenShield", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "disableScreenShield", returnType: CAPPluginReturnPromise)
    ]

    private var secureTextField: UITextField?

    @objc func authenticateWithBiometrics(_ call: CAPPluginCall) {
        let reason = call.getString("reason") ?? "验证 Face ID 以确认 Pearl 转账交易"
        let context = LAContext()
        context.localizedCancelTitle = "取消"
        var error: NSError?

        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, evalError in
                DispatchQueue.main.async {
                    if success {
                        call.resolve([
                            "success": true,
                            "type": context.biometryType == .faceID ? "faceID" : "touchID"
                        ])
                    } else {
                        let errMsg = evalError?.localizedDescription ?? "Face ID 验证未通过"
                        call.reject(errMsg)
                    }
                }
            }
        } else if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
            // 设备无 Face ID 或未录入时，回退至系统密码
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, evalError in
                DispatchQueue.main.async {
                    if success {
                        call.resolve(["success": true, "type": "passcode"])
                    } else {
                        call.reject("系统密码认证未通过")
                    }
                }
            }
        } else {
            call.reject("该设备未开启生物识别或系统锁屏密码")
        }
    }

    @objc func enableScreenShield(_ call: CAPPluginCall) {
        DispatchQueue.main.async {
            if self.secureTextField == nil {
                let field = UITextField()
                field.isSecureTextEntry = true
                self.bridge?.viewController?.view.addSubview(field)
                field.centerYAnchor.constraint(equalTo: self.bridge!.viewController!.view.centerYAnchor).isActive = true
                field.centerXAnchor.constraint(equalTo: self.bridge!.viewController!.view.centerXAnchor).isActive = true
                self.bridge?.viewController?.view.layer.superlayer?.addSublayer(field.layer)
                field.layer.sublayers?.first?.addSublayer(self.bridge!.viewController!.view.layer)
                self.secureTextField = field
            }
            call.resolve(["shielded": true])
        }
    }

    @objc func disableScreenShield(_ call: CAPPluginCall) {
        DispatchQueue.main.async {
            self.secureTextField?.removeFromSuperview()
            self.secureTextField = nil
            call.resolve(["shielded": false])
        }
    }
}
