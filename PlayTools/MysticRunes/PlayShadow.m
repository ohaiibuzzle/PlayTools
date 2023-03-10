//
//  PlayMask.m
//  PlayTools
//
//  Created by Venti on 08/03/2023.
//

#import <Foundation/Foundation.h>
#import "NSObject+Swizzle.h"
#import <objc/runtime.h>

__attribute__((visibility("hidden")))
@interface PlayShadowLoader : NSObject
@end

@implementation NSObject (Swizzle)

- (void) swizzleInstanceMethod:(SEL)origSelector withMethod:(SEL)newSelector
{
    Class cls = [self class];
    // If current class doesn't exist selector, then get super
    Method originalMethod = class_getInstanceMethod(cls, origSelector);
    Method swizzledMethod = class_getInstanceMethod(cls, newSelector);
    
    // Add selector if it doesn't exist, implement append with method
    if (class_addMethod(cls,
                        origSelector,
                        method_getImplementation(swizzledMethod),
                        method_getTypeEncoding(swizzledMethod)) ) {
        // Replace class instance method, added if selector not exist
        // For class cluster, it always adds new selector here
        class_replaceMethod(cls,
                            newSelector,
                            method_getImplementation(originalMethod),
                            method_getTypeEncoding(originalMethod));
        
    } else {
        // SwizzleMethod maybe belongs to super
        class_replaceMethod(cls,
                            newSelector,
                            class_replaceMethod(cls,
                                                origSelector,
                                                method_getImplementation(swizzledMethod),
                                                method_getTypeEncoding(swizzledMethod)),
                            method_getTypeEncoding(originalMethod));
    }
}

- (NSInteger) hook_deviceType {
    return 1;
}

- (BOOL) pm_return_false {
    // NSLog(@"PC-DEBUG: [PlayMask] Jailbreak Detection Attempted");
    return false;
}

- (BOOL) pm_return_true {
    // NSLog(@"PC-DEBUG: [PlayMask] Jailbreak Detection Attempted");
    return true;
}

- (BOOL) pm_return_yes {
    // NSLog(@"PC-DEBUG: [PlayMask] Jailbreak Detection Attempted");
    return YES;
}

- (BOOL) pm_return_no {
    // NSLog(@"PC-DEBUG: [PlayMask] Jailbreak Detection Attempted");
    return NO;
}

- (int) pm_return_0 {
    // NSLog(@"PC-DEBUG: [PlayMask] Jailbreak Detection Attempted");
    return 0;
}

- (int) pm_return_1 {
    // NSLog(@"PC-DEBUG: [PlayMask] Jailbreak Detection Attempted");
    return 1;
}

- (NSString *) pm_return_empty {
    // NSLog(@"PC-DEBUG: [PlayMask] Jailbreak Detection Attempted");
    return @"";
}

@end

@implementation PlayShadowLoader

+ (void) load {
    // Swizzle NSProcessInfo to troll every app that tries to detect macCatalyst
    // [objc_getClass("NSProcessInfo") swizzleInstanceMethod:@selector(isMacCatalystApp) withMethod:@selector(pm_return_false)];
    // [objc_getClass("NSProcessInfo") swizzleInstanceMethod:@selector(isiOSAppOnMac) withMethod:@selector(pm_return_true)];

    [objc_getClass("RNDeviceInfo") swizzleInstanceMethod:@selector(getDeviceType) withMethod:@selector(hook_deviceType)];
    
    // Class: UIDevice
    [objc_getClass("UIDevice") swizzleInstanceMethod:@selector(isJailbroken) withMethod:@selector(pm_return_no)];
    [objc_getClass("UIDevice") swizzleInstanceMethod:@selector(isJailBreak) withMethod:@selector(pm_return_no)];
    [objc_getClass("UIDevice") swizzleInstanceMethod:@selector(isJailBroken) withMethod:@selector(pm_return_no)];

    // Class: JailbreakDetectionVC
    [objc_getClass("JailbreakDetectionVC") swizzleInstanceMethod:@selector(isJailbroken) withMethod:@selector(pm_return_no)];

    // Class: DTTJailbreakDetection
    [objc_getClass("DTTJailbreakDetection") swizzleInstanceMethod:@selector(isJailbroken) withMethod:@selector(pm_return_no)];

    // Class: ANSMetadata
    [objc_getClass("ANSMetadata") swizzleInstanceMethod:@selector(computeIsJailbroken) withMethod:@selector(pm_return_no)];
    [objc_getClass("ANSMetadata") swizzleInstanceMethod:@selector(isJailbroken) withMethod:@selector(pm_return_no)];

    // Class: AppsFlyerUtils
    [objc_getClass("AppsFlyerUtils") swizzleInstanceMethod:@selector(isJailBreakon) withMethod:@selector(pm_return_no)];
    [objc_getClass("AppsFlyerUtils") swizzleInstanceMethod:@selector(a) withMethod:@selector(pm_return_false)];

    // Class: jailBreak
    [objc_getClass("jailBreak") swizzleInstanceMethod:@selector(isJailBreak) withMethod:@selector(pm_return_false)];

    // Class: GBDeviceInfo
    [objc_getClass("GBDeviceInfo") swizzleInstanceMethod:@selector(isJailbroken) withMethod:@selector(pm_return_no)];

    // Class: CMARAppRestrictionsDelegate
    [objc_getClass("CMARAppRestrictionsDelegate") swizzleInstanceMethod:@selector(isDeviceNonCompliant) withMethod:@selector(pm_return_false)];

    // Class: ADYSecurityChecks
    [objc_getClass("ADYSecurityChecks") swizzleInstanceMethod:@selector(isDeviceJailbroken) withMethod:@selector(pm_return_false)];

    // Class: UBReportMetadataDevice
    [objc_getClass("UBReportMetadataDevice") swizzleInstanceMethod:@selector(is_rooted) withMethod:@selector(pm_return_null)];

    // Class: UtilitySystem
    [objc_getClass("UtilitySystem") swizzleInstanceMethod:@selector(isJailbreak) withMethod:@selector(pm_return_false)];

    // Class: GemaltoConfiguration
    [objc_getClass("GemaltoConfiguration") swizzleInstanceMethod:@selector(isJailbreak) withMethod:@selector(pm_return_false)];

    // Class: CPWRDeviceInfo
    [objc_getClass("CPWRDeviceInfo") swizzleInstanceMethod:@selector(isJailbroken) withMethod:@selector(pm_return_false)];

    // Class: CPWRSessionInfo
    [objc_getClass("CPWRSessionInfo") swizzleInstanceMethod:@selector(isJailbroken) withMethod:@selector(pm_return_false)];

    // Class: KSSystemInfo
    [objc_getClass("KSSystemInfo") swizzleInstanceMethod:@selector(isJailbroken) withMethod:@selector(pm_return_false)];

    // Class: EMDSKPPConfiguration
    [objc_getClass("EMDSKPPConfiguration") swizzleInstanceMethod:@selector(jailBroken) withMethod:@selector(pm_return_false)];

    // Class: EnrollParameters
    [objc_getClass("EnrollParameters") swizzleInstanceMethod:@selector(jailbroken) withMethod:@selector(pm_return_null)];

    // Class: EMDskppConfigurationBuilder
    [objc_getClass("EMDskppConfigurationBuilder") swizzleInstanceMethod:@selector(jailbreakStatus) withMethod:@selector(pm_return_false)];

    // Class: FCRSystemMetadata
    [objc_getClass("FCRSystemMetadata") swizzleInstanceMethod:@selector(isJailbroken) withMethod:@selector(pm_return_false)];

    // Class: v_VDMap
    [objc_getClass("v_VDMap") swizzleInstanceMethod:@selector(isJailbrokenDetected) withMethod:@selector(pm_return_false)];
    [objc_getClass("v_VDMap") swizzleInstanceMethod:@selector(isJailBrokenDetectedByVOS) withMethod:@selector(pm_return_false)];
    [objc_getClass("v_VDMap") swizzleInstanceMethod:@selector(isDFPHookedDetecedByVOS) withMethod:@selector(pm_return_false)];
    [objc_getClass("v_VDMap") swizzleInstanceMethod:@selector(isCodeInjectionDetectedByVOS) withMethod:@selector(pm_return_false)];
    [objc_getClass("v_VDMap") swizzleInstanceMethod:@selector(isDebuggerCheckDetectedByVOS) withMethod:@selector(pm_return_false)];
    [objc_getClass("v_VDMap") swizzleInstanceMethod:@selector(isAppSignerCheckDetectedByVOS) withMethod:@selector(pm_return_false)];
    [objc_getClass("v_VDMap") swizzleInstanceMethod:@selector(v_checkAModified) withMethod:@selector(pm_return_false)];
    [objc_getClass("v_VDMap") swizzleInstanceMethod:@selector(isRuntimeTamperingDetected) withMethod:@selector(pm_return_false)];

    // Class: SDMUtils
    [objc_getClass("SDMUtils") swizzleInstanceMethod:@selector(isJailBroken) withMethod:@selector(pm_return_no)];

    // Class: OneSignalJailbreakDetection
    [objc_getClass("OneSignalJailbreakDetection") swizzleInstanceMethod:@selector(isJailbroken) withMethod:@selector(pm_return_no)];

    // Class: DigiPassHandler
    [objc_getClass("DigiPassHandler") swizzleInstanceMethod:@selector(rootedDeviceTestResult) withMethod:@selector(pm_return_no)];

    // Class: AWMyDeviceGeneralInfo
    [objc_getClass("AWMyDeviceGeneralInfo") swizzleInstanceMethod:@selector(isCompliant) withMethod:@selector(pm_return_true)];

    // Class: DTXSessionInfo
    [objc_getClass("DTXSessionInfo") swizzleInstanceMethod:@selector(isJailbroken) withMethod:@selector(pm_return_false)];

    // Class: DTXDeviceInfo
    [objc_getClass("DTXDeviceInfo") swizzleInstanceMethod:@selector(isJailbroken) withMethod:@selector(pm_return_false)];

    // Class: JailbreakDetection
    [objc_getClass("JailbreakDetection") swizzleInstanceMethod:@selector(jailbroken) withMethod:@selector(pm_return_false)];

    // Class: jailBrokenJudge
    [objc_getClass("jailBrokenJudge") swizzleInstanceMethod:@selector(isJailBreak) withMethod:@selector(pm_return_false)];
    [objc_getClass("jailBrokenJudge") swizzleInstanceMethod:@selector(isCydiaJailBreak) withMethod:@selector(pm_return_false)];
    [objc_getClass("jailBrokenJudge") swizzleInstanceMethod:@selector(isApplicationsJailBreak) withMethod:@selector(pm_return_false)];
    [objc_getClass("jailBrokenJudge") swizzleInstanceMethod:@selector(ischeckCydiaJailBreak) withMethod:@selector(pm_return_false)];
    [objc_getClass("jailBrokenJudge") swizzleInstanceMethod:@selector(isPathJailBreak) withMethod:@selector(pm_return_false)];
    [objc_getClass("jailBrokenJudge") swizzleInstanceMethod:@selector(boolIsjailbreak) withMethod:@selector(pm_return_false)];

    // Class: FBAdBotDetector
    [objc_getClass("FBAdBotDetector") swizzleInstanceMethod:@selector(isJailBrokenDevice) withMethod:@selector(pm_return_false)];

    // Class: TNGDeviceTool
    [objc_getClass("TNGDeviceTool") swizzleInstanceMethod:@selector(isJailBreak) withMethod:@selector(pm_return_false)];
    [objc_getClass("TNGDeviceTool") swizzleInstanceMethod:@selector(isJailBreak_file) withMethod:@selector(pm_return_false)];
    [objc_getClass("TNGDeviceTool") swizzleInstanceMethod:@selector(isJailBreak_cydia) withMethod:@selector(pm_return_false)];
    [objc_getClass("TNGDeviceTool") swizzleInstanceMethod:@selector(isJailBreak_appList) withMethod:@selector(pm_return_false)];
    [objc_getClass("TNGDeviceTool") swizzleInstanceMethod:@selector(isJailBreak_env) withMethod:@selector(pm_return_false)];

    // Class: DTDeviceInfo
    [objc_getClass("DTDeviceInfo") swizzleInstanceMethod:@selector(isJailbreak) withMethod:@selector(pm_return_false)];

    // Class: SecVIDeviceUtil
    [objc_getClass("SecVIDeviceUtil") swizzleInstanceMethod:@selector(isJailbreak) withMethod:@selector(pm_return_false)];

    // Class: RVPBridgeExtension4Jailbroken
    [objc_getClass("RVPBridgeExtension4Jailbroken") swizzleInstanceMethod:@selector(isJailbroken) withMethod:@selector(pm_return_false)];

    // Class: ZDetection
    [objc_getClass("ZDetection") swizzleInstanceMethod:@selector(isRootedOrJailbroken) withMethod:@selector(pm_return_false)];
}

@end
