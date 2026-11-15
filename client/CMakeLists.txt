cmake_minimum_required(VERSION 3.21)

project(SecTradePasskeyClient VERSION 1.0.0 LANGUAGES CXX)

if(APPLE)
    enable_language(OBJCXX)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

add_compile_options($<$<CXX_COMPILER_ID:MSVC>:/utf-8>)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Network Qml Quick QuickControls2)

set(PROJECT_SOURCES
    src/main.cpp
    src/passkey/PasskeyTypes.h
    src/passkey/IPasskeyProvider.h
    src/passkey/PasskeyManager.h
    src/passkey/PasskeyManager.cpp
    src/bridge/CefPasskeyBridge.h
    resources.qrc
)

if(WIN32)
    list(APPEND PROJECT_SOURCES src/passkey/PasskeyProvider_win.cpp)
elseif(APPLE)
    list(APPEND PROJECT_SOURCES src/passkey/PasskeyProvider_apple.mm)
endif()

qt_add_executable(SecTradePasskeyClient
    MANUAL_FINALIZATION
    ${PROJECT_SOURCES}
)

target_link_libraries(SecTradePasskeyClient PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Network
    Qt6::Qml
    Qt6::Quick
    Qt6::QuickControls2
)

if(WIN32)
    target_link_libraries(SecTradePasskeyClient PRIVATE user32)
    set_target_properties(SecTradePasskeyClient PROPERTIES WIN32_EXECUTABLE FALSE)
elseif(APPLE)
    find_library(AUTH_SERVICES_LIB AuthenticationServices REQUIRED)
    find_library(FOUNDATION_LIB Foundation REQUIRED)
    target_link_libraries(SecTradePasskeyClient PRIVATE
        ${AUTH_SERVICES_LIB}
        ${FOUNDATION_LIB}
    )
    if(IOS)
        find_library(UIKIT_LIB UIKit REQUIRED)
        target_link_libraries(SecTradePasskeyClient PRIVATE ${UIKIT_LIB})
    else()
        find_library(APPKIT_LIB AppKit REQUIRED)
        target_link_libraries(SecTradePasskeyClient PRIVATE ${APPKIT_LIB})
    endif()
    set_target_properties(SecTradePasskeyClient PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_GUI_IDENTIFIER "com.sectrade.passkeydemo"
        XCODE_ATTRIBUTE_CODE_SIGN_ENTITLEMENTS "${CMAKE_CURRENT_SOURCE_DIR}/apple/SecTradePasskey.entitlements"
    )
endif()

qt_finalize_executable(SecTradePasskeyClient)
