import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ApplicationWindow {
    id: rootWindow
    width: 1060
    height: 740
    minimumWidth: 900
    minimumHeight: 640
    visible: true
    title: "SecTrade Pro 证券分析终端 — 跨平台 Passkey (FIDO2/WebAuthn) 原生认证示例"
    color: "#0D1117"

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 20
        spacing: 14

        // ====================================================================
        // 顶部状态栏：显示当前操作系统原生 API 驱动、硬件可用性与服务端连接状态
        // ====================================================================
        Rectangle {
            Layout.fillWidth: true
            height: 76
            radius: 10
            color: "#161B22"
            border.color: "#30363D"
            border.width: 1

            RowLayout {
                anchors.fill: parent
                anchors.margins: 14
                spacing: 16

                ColumnLayout {
                    spacing: 4
                    Text {
                        text: "SecTrade 证券分析终端 · Passkey 硬件安全登录"
                        color: "#F0F6FC"
                        font.pixelSize: 18
                        font.bold: true
                    }
                    Text {
                        text: "底层驱动: " + passkeyManager.platformName + "  |  " + passkeyManager.hardwareDetail
                        color: passkeyManager.hardwareAvailable ? "#3FB950" : "#D29922"
                        font.pixelSize: 12
                    }
                }

                Item { Layout.fillWidth: true }

                Rectangle {
                    radius: 6
                    color: passkeyManager.serverOnline ? "#122D1F" : "#341A1E"
                    border.color: passkeyManager.serverOnline ? "#2EA043" : "#F85149"
                     implicitWidth: srvStatusText.implicitWidth + 24
                    implicitHeight: 34

                    Text {
                        id: srvStatusText
                        anchors.centerIn: parent
                        text: passkeyManager.serverOnline ? "● 认证服务端在线" : "● 认证服务端离线"
                        color: passkeyManager.serverOnline ? "#3FB950" : "#FF7B72"
                        font.pixelSize: 13
                        font.bold: true
                    }
                }
            }
        }

        // ====================================================================
        // 服务端地址与 RP_ID 配置栏 (支持本地无域名测试 + 阿里云 IP / 隧道域名切换)
        // ====================================================================
        Rectangle {
            Layout.fillWidth: true
            height: 62
            radius: 8
            color: "#161B22"
            border.color: "#30363D"

            RowLayout {
                anchors.fill: parent
                anchors.margins: 12
                spacing: 12

                Text {
                    text: "Server URL (本地或阿里云):"
                    color: "#8B949E"
                    font.pixelSize: 13
                }

                TextField {
                    id: serverUrlField
                    Layout.preferredWidth: 260
                    text: passkeyManager.serverUrl
                    placeholderText: "http://127.0.0.1:8000 或 http://阿里云IP:8000"
                    color: "#E6EDF3"
                    font.pixelSize: 13
                    background: Rectangle {
                        color: "#0D1117"
                        radius: 6
                        border.color: serverUrlField.activeFocus ? "#58A6FF" : "#30363D"
                    }
                    onEditingFinished: passkeyManager.serverUrl = text
                }

                Text {
                    text: "RP_ID (依赖方域名):"
                    color: "#8B949E"
                    font.pixelSize: 13
                }

                TextField {
                    id: rpIdField
                    Layout.preferredWidth: 180
                    text: passkeyManager.rpId
                    placeholderText: "localhost"
                    color: "#E6EDF3"
                    font.pixelSize: 13
                    background: Rectangle {
                        color: "#0D1117"
                        radius: 6
                        border.color: rpIdField.activeFocus ? "#58A6FF" : "#30363D"
                    }
                    onEditingFinished: passkeyManager.rpId = text
                }

                Button {
                    text: "应用并检测连接"
                    onClicked: {
                        passkeyManager.serverUrl = serverUrlField.text
                        passkeyManager.rpId = rpIdField.text
                        passkeyManager.checkServerHealth()
                    }
                }

                Item { Layout.fillWidth: true }
            }
        }

        // ====================================================================
        // 主体双栏区域：左侧「证券账户 Passkey 注册/登录面板」，右侧「已绑定凭证 & 协议日志」
        // ====================================================================
        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 16

            // 左侧操作卡片
            Rectangle {
                Layout.preferredWidth: 420
                Layout.fillHeight: true
                radius: 10
                color: "#161B22"
                border.color: "#30363D"

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 20
                    spacing: 16

                    Text {
                        text: passkeyManager.loggedInUser.length > 0
                              ? "✅ 已登录证券交易会话"
                              : "🔐 证券账户 Passkey 认证"
                        color: "#F0F6FC"
                        font.pixelSize: 17
                        font.bold: true
                    }

                    // 登录成功后的用户信息展示卡
                    Rectangle {
                        Layout.fillWidth: true
                        visible: passkeyManager.loggedInUser.length > 0
                        height: 110
                        radius: 8
                        color: "#0F291E"
                        border.color: "#2EA043"

                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 12
                            spacing: 6

                            Text {
                                text: "当前登录资金账号: " + passkeyManager.loggedInUser
                                color: "#3FB950"
                                font.pixelSize: 15
                                font.bold: true
                            }
                            Text {
                                text: "会话 JWT: " + passkeyManager.sessionToken
                                color: "#8B949E"
                                font.pixelSize: 12
                                elide: Text.ElideMiddle
                                Layout.fillWidth: true
                            }
                            Button {
                                text: "退出当前登录态"
                                onClicked: passkeyManager.logout()
                            }
                        }
                    }

                    Text {
                        text: "证券资金账号 / 用户名:"
                        color: "#C9D1D9"
                        font.pixelSize: 13
                    }

                    TextField {
                        id: usernameInput
                        Layout.fillWidth: true
                        height: 40
                        text: "88001688"
                        placeholderText: "输入客户号或用户名 (如 88001688)"
                        color: "#F0F6FC"
                        font.pixelSize: 14
                        background: Rectangle {
                            color: "#0D1117"
                            radius: 6
                            border.color: usernameInput.activeFocus ? "#58A6FF" : "#30363D"
                        }
                    }

                    Text {
                        text: "账户别名 (显示在系统生物识别弹窗中):"
                        color: "#C9D1D9"
                        font.pixelSize: 13
                    }

                    TextField {
                        id: displayNameInput
                        Layout.fillWidth: true
                        height: 40
                        text: "张先生 (VIP量化账户)"
                        placeholderText: "选填，如：张先生 (A股/港美股账户)"
                        color: "#F0F6FC"
                        font.pixelSize: 14
                        background: Rectangle {
                            color: "#0D1117"
                            radius: 6
                            border.color: displayNameInput.activeFocus ? "#58A6FF" : "#30363D"
                        }
                    }

                    // 按钮组
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 10

                        Button {
                            Layout.fillWidth: true
                            height: 44
                            enabled: !passkeyManager.busy
                            background: Rectangle {
                                radius: 7
                                color: parent.enabled ? (parent.down ? "#1F6FEB" : "#238636") : "#21262D"
                            }
                            contentItem: Text {
                                text: "1. 注册绑定本机 Passkey (MakeCredential)"
                                color: "#FFFFFF"
                                font.pixelSize: 14
                                font.bold: true
                                horizontalAlignment: Text.AlignHCenter
                                verticalAlignment: Text.AlignVCenter
                            }
                            onClicked: passkeyManager.registerPasskey(usernameInput.text, displayNameInput.text)
                        }

                        Button {
                            Layout.fillWidth: true
                            height: 44
                            enabled: !passkeyManager.busy
                            background: Rectangle {
                                radius: 7
                                color: parent.enabled ? (parent.down ? "#1158C7" : "#1F6FEB") : "#21262D"
                            }
                            contentItem: Text {
                                text: "2. 使用指定账号 Passkey 登录 (GetAssertion)"
                                color: "#FFFFFF"
                                font.pixelSize: 14
                                font.bold: true
                                horizontalAlignment: Text.AlignHCenter
                                verticalAlignment: Text.AlignVCenter
                            }
                            onClicked: passkeyManager.loginWithPasskey(usernameInput.text)
                        }

                        Button {
                            Layout.fillWidth: true
                            height: 40
                            enabled: !passkeyManager.busy
                            background: Rectangle {
                                radius: 7
                                color: parent.enabled ? "#21262D" : "#161B22"
                                border.color: "#58A6FF"
                            }
                            contentItem: Text {
                                text: "3. 免输账号一键发现式登录 (Discoverable ResidentKey)"
                                color: "#58A6FF"
                                font.pixelSize: 13
                                horizontalAlignment: Text.AlignHCenter
                                verticalAlignment: Text.AlignVCenter
                            }
                            onClicked: passkeyManager.loginWithPasskey("")
                        }

                        Button {
                            Layout.fillWidth: true
                            height: 36
                            visible: passkeyManager.busy
                            text: "取消当前系统生物识别弹窗"
                            onClicked: passkeyManager.cancelOperation()
                        }
                    }

                    Item { Layout.fillHeight: true }

                    // 实时状态提示条
                    Rectangle {
                        Layout.fillWidth: true
                        height: 54
                        radius: 6
                        color: "#0D1117"
                        border.color: "#30363D"

                        Text {
                            anchors.fill: parent
                            anchors.margins: 10
                            text: passkeyManager.statusMessage
                            color: "#58A6FF"
                            font.pixelSize: 12
                            wrapMode: Text.Wrap
                            verticalAlignment: Text.AlignVCenter
                        }
                    }
                }
            }

            // 右侧：上部分为「服务端已注册公钥列表」，下部分为「WebAuthn 底层协议报文追踪」
            ColumnLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                spacing: 14

                // 服务端已注册凭证列表
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 220
                    radius: 10
                    color: "#161B22"
                    border.color: "#30363D"

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 14
                        spacing: 8

                        RowLayout {
                            Layout.fillWidth: true
                            Text {
                                text: "📋 服务端已注册的 Passkey 硬件公钥列表 (" + passkeyManager.registeredCredentials.length + ")"
                                color: "#F0F6FC"
                                font.pixelSize: 14
                                font.bold: true
                            }
                            Item { Layout.fillWidth: true }
                            Button {
                                text: "刷新列表"
                                onClicked: passkeyManager.refreshRegisteredUsers()
                            }
                        }

                        ListView {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            clip: true
                            spacing: 6
                            model: passkeyManager.registeredCredentials

                            delegate: Rectangle {
                                width: ListView.view.width
                                height: 46
                                radius: 6
                                color: "#0D1117"
                                border.color: "#21262D"

                                RowLayout {
                                    anchors.fill: parent
                                    anchors.leftMargin: 12
                                    anchors.rightMargin: 12
                                    spacing: 10

                                    Text {
                                        text: "账号: " + modelData.username + " (" + modelData.display_name + ")"
                                        color: "#58A6FF"
                                        font.pixelSize: 13
                                        font.bold: true
                                    }

                                    Text {
                                        text: "RP: " + modelData.rp_id + " | 签名计数: " + modelData.sign_count
                                        color: "#8B949E"
                                        font.pixelSize: 12
                                    }

                                    Text {
                                        text: "ID: " + modelData.credential_id.substring(0, 16) + "..."
                                        color: "#6E7681"
                                        font.pixelSize: 12
                                        Layout.fillWidth: true
                                        elide: Text.ElideRight
                                    }

                                    Button {
                                        text: "删除"
                                        onClicked: passkeyManager.deleteUser(modelData.username)
                                    }
                                }
                            }
                        }
                    }
                }

                // 底层协议交互日志
                Rectangle {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    radius: 10
                    color: "#161B22"
                    border.color: "#30363D"

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 14
                        spacing: 8

                        RowLayout {
                            Layout.fillWidth: true
                            Text {
                                text: "🔍 FIDO2 / WebAuthn 原生 C++ 协议追踪日志"
                                color: "#F0F6FC"
                                font.pixelSize: 14
                                font.bold: true
                            }
                            Item { Layout.fillWidth: true }
                            Button {
                                text: "清空日志"
                                onClicked: passkeyManager.clearLogs()
                            }
                        }

                        ScrollView {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            clip: true

                            TextArea {
                                readOnly: true
                                text: passkeyManager.protocolLog
                                color: "#7EE787"
                                font.family: "Consolas"
                                font.pixelSize: 12
                                wrapMode: TextEdit.Wrap
                                background: Rectangle {
                                    color: "#090D11"
                                    radius: 6
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
