//
//  PleaseKillMySSL.m
//  PlayTools
//
//  Created by Venti on 18/04/2023.
//

/*
 WARNING: Running unleash_ssl_hooks(); from your code is something that heaven forbids.
 PLEASE DON'T F-ING DO IT
 */

#import <Foundation/Foundation.h>
#import <Security/SecureTransport.h>
#import "fishhook.h"
#import <dlfcn.h>
#import "PleaseKillMySSL.h"

#pragma mark SecureTransport hooks - iOS 9 and below
// Explanation here: https://nabla-c0d3.github.io/blog/2013/08/20/ios-ssl-kill-switch-v0-dot-5-released/

static OSStatus (*original_SSLSetSessionOption)(SSLContextRef context,
                                                SSLSessionOption option,
                                                Boolean value);

static OSStatus replaced_SSLSetSessionOption(SSLContextRef context,
                                             SSLSessionOption option,
                                             Boolean value)
{
    // Remove the ability to modify the value of the kSSLSessionOptionBreakOnServerAuth option
    if (option == kSSLSessionOptionBreakOnServerAuth)
    {
        return noErr;
    }
    return original_SSLSetSessionOption(context, option, value);
}


static SSLContextRef (*original_SSLCreateContext)(CFAllocatorRef alloc,
                                                  SSLProtocolSide protocolSide,
                                                  SSLConnectionType connectionType);

static SSLContextRef replaced_SSLCreateContext(CFAllocatorRef alloc,
                                               SSLProtocolSide protocolSide,
                                               SSLConnectionType connectionType)
{
    SSLContextRef sslContext = original_SSLCreateContext(alloc, protocolSide, connectionType);

    // Immediately set the kSSLSessionOptionBreakOnServerAuth option in order to disable cert validation
    original_SSLSetSessionOption(sslContext, kSSLSessionOptionBreakOnServerAuth, true);
    return sslContext;
}


static OSStatus (*original_SSLHandshake)(SSLContextRef context);

static OSStatus replaced_SSLHandshake(SSLContextRef context)
{

    OSStatus result = original_SSLHandshake(context);

    // Hijack the flow when breaking on server authentication
    if (result == errSSLServerAuthCompleted)
    {
        // Do not check the cert and call SSLHandshake() again
        return original_SSLHandshake(context);
    }

    return result;
}


#pragma mark libsystem_coretls.dylib hooks - iOS 10
// Explanation here: https://nabla-c0d3.github.io/blog/2017/02/05/ios10-ssl-kill-switch/

static OSStatus (*original_tls_helper_create_peer_trust)(void *hdsk, bool server, SecTrustRef *trustRef);

static OSStatus replaced_tls_helper_create_peer_trust(void *hdsk, bool server, SecTrustRef *trustRef)
{
    // Do not actually set the trustRef
    return errSecSuccess;
}


#pragma mark BoringSSL hooks - iOS 12
// Explanation here: https://nabla-c0d3.github.io/blog/2019/05/18/ssl-kill-switch-for-ios12/

// Everyone's favorite OpenSSL constant
#define SSL_VERIFY_NONE 0

// Constant defined in BoringSSL
enum ssl_verify_result_t {
    ssl_verify_ok = 0,
    ssl_verify_invalid,
    ssl_verify_retry,
};


char *replaced_SSL_get_psk_identity(void *ssl)
{
    return "notarealPSKidentity";
}


static int custom_verify_callback_that_does_not_validate(void *ssl, uint8_t *out_alert)
{
    // Yes this certificate is 100% valid...
    return ssl_verify_ok;
}


static void (*original_SSL_CTX_set_custom_verify)(void *ctx, int mode, int (*callback)(void *ssl, uint8_t *out_alert));
static void replaced_SSL_CTX_set_custom_verify(void *ctx, int mode, int (*callback)(void *ssl, uint8_t *out_alert))
{
    NSLog(@"Entering replaced_SSL_CTX_set_custom_verify()");
    original_SSL_CTX_set_custom_verify(ctx, SSL_VERIFY_NONE, custom_verify_callback_that_does_not_validate);
    return;
}


static void (*original_SSL_set_custom_verify)(void *ssl, int mode, int (*callback)(void *ssl, uint8_t *out_alert));
static void replaced_SSL_set_custom_verify(void *ssl, int mode, int (*callback)(void *ssl, uint8_t *out_alert))
{
    NSLog(@"Entering replaced_SSL_set_custom_verify()");
    original_SSL_set_custom_verify(ssl, SSL_VERIFY_NONE, custom_verify_callback_that_does_not_validate);
    return;
}


void unleash_ssl_hooks(void)
{
    // Fishhook-based hooking, for OS X builds; always hook
    NSLog(@"Fishhook hook enabled.");
    original_SSLHandshake = dlsym(RTLD_DEFAULT, "SSLHandshake");
    if ((rebind_symbols((struct rebinding[1]){{(char *)"SSLHandshake", (void *)replaced_SSLHandshake}}, 1) < 0))
    {
        NSLog(@"Hooking failed.");
    }

    original_SSLSetSessionOption = dlsym(RTLD_DEFAULT, "SSLSetSessionOption");
    if ((rebind_symbols((struct rebinding[1]){{(char *)"SSLSetSessionOption", (void *)replaced_SSLSetSessionOption}}, 1) < 0))
    {
        NSLog(@"Hooking failed.");
    }

    original_SSLCreateContext = dlsym(RTLD_DEFAULT, "SSLCreateContext");
    if ((rebind_symbols((struct rebinding[1]){{(char *)"SSLCreateContext", (void *)replaced_SSLCreateContext}}, 1) < 0))
    {
        NSLog(@"Hooking failed.");
    }

    original_tls_helper_create_peer_trust = dlsym(RTLD_DEFAULT, "tls_helper_create_peer_trust");
    if ((rebind_symbols((struct rebinding[1]){{(char *)"tls_helper_create_peer_trust", (void *)replaced_tls_helper_create_peer_trust}}, 1) < 0))
    {
        NSLog(@"Hooking failed.");
    }

    original_SSL_CTX_set_custom_verify = dlsym(RTLD_DEFAULT, "SSL_CTX_set_custom_verify");
    if ((rebind_symbols((struct rebinding[1]){{(char *)"SSL_CTX_set_custom_verify", (void *)replaced_SSL_CTX_set_custom_verify}}, 1) < 0))
    {
        NSLog(@"Hooking failed.");
    }

    original_SSL_set_custom_verify = dlsym(RTLD_DEFAULT, "SSL_set_custom_verify");
    if ((rebind_symbols((struct rebinding[1]){{(char *)"SSL_set_custom_verify", (void *)replaced_SSL_set_custom_verify}}, 1) < 0))
    {
        NSLog(@"Hooking failed.");
    }

    NSLog(@"Fishhook hook complete.");
    
}

