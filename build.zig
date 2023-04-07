// TODO:
// - generate Version.hpp
// - vendor deps
// - ffmpeg
// - curl ssl
// - use msvc ABI for Windows
// - get Windows building
// - clean this shit up

const std = @import("std");

const dep_config_dir = "deps/include";

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{
        .default_target = std.zig.CrossTarget.parse(.{
            .arch_os_abi = "x86-linux-gnu", // TODO native os
        }) catch unreachable,
    });
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addSharedLibrary(.{
        .name = "sar",
        .target = target,
        .optimize = optimize,
    });

    lib.linker_allow_shlib_undefined = false;
    if (target.getOsTag() == .windows) {
        lib.want_lto = false; // ziglang/zig#8531
    }

    if (target.isWindows()) lib.defineCMacro("_WIN32", null);

    lib.addIncludePath("deps/curl/include");
    lib.addIncludePath("deps/SFML/include");
    lib.linkLibrary(buildCurl(b, target, optimize));
    lib.linkLibrary(buildSfml(b, target, optimize));

    lib.linkLibC();
    lib.linkLibCpp();
    lib.defineCMacro("CURL_STATICLIB", null);
    lib.defineCMacro("_GNU_SOURCE", null);
    lib.addIncludePath("src");
    lib.addCSourceFiles(&sar_cpp_sources, &.{
        "-fno-sanitize=alignment", // we misuse pointer alignment all over the place
        "-fno-sanitize=shift", // ed25519 uses this
        "-std=c++17",
        "-Wall",
        "-Werror",
        "-Wno-delete-non-abstract-non-virtual-dtor",
        "-Wno-overloaded-virtual",
        "-Wno-unknown-pragmas",
        "-Wno-mismatched-tags",
        "-Wno-inconsistent-missing-override",
        "-Wno-unqualified-std-cast-call",
        "-Wno-missing-braces",
        "-Wno-non-pod-varargs",
        "-Wno-return-stack-address",
        "-Wno-parentheses",
        "-Wno-unused-private-field",
        "-Wno-absolute-value",
    });
    lib.install();
}

const sar_cpp_sources = [_][]const u8{
    "src/Checksum.cpp",
    "src/Event.cpp",
    "src/Plugin.cpp",
    "src/Cheats.cpp",
    "src/Entity.cpp",
    "src/Features/Updater.cpp",
    "src/Features/Timer/PauseTimer.cpp",
    "src/Features/Timer/TimerAverage.cpp",
    "src/Features/Timer/Timer.cpp",
    "src/Features/Timer/TimerCheckPoints.cpp",
    "src/Features/ClassDumper.cpp",
    "src/Features/Summary.cpp",
    "src/Features/Teleporter.cpp",
    "src/Features/FovChanger.cpp",
    "src/Features/Camera.cpp",
    "src/Features/GroundFramesCounter.cpp",
    "src/Features/TimescaleDetect.cpp",
    "src/Features/ConfigPlus.cpp",
    "src/Features/Feature.cpp",
    "src/Features/NetMessage.cpp",
    "src/Features/WindowResizer.cpp",
    "src/Features/DataMapDumper.cpp",
    "src/Features/StepCounter.cpp",
    "src/Features/Stats/StepStats.cpp",
    "src/Features/Stats/JumpStats.cpp",
    "src/Features/Stats/Stats.cpp",
    "src/Features/Stats/StatsCounter.cpp",
    "src/Features/Stats/VelocityStats.cpp",
    "src/Features/Stats/Sync.cpp",
    "src/Features/FCPS.cpp",
    //"src/Features/Renderer.cpp", TODO
    "src/Features/Demo/DemoGhostPlayer.cpp",
    "src/Features/Demo/DemoGhostEntity.cpp",
    "src/Features/Demo/GhostEntity.cpp",
    "src/Features/Demo/DemoParser.cpp",
    "src/Features/Demo/GhostRenderer.cpp",
    "src/Features/Demo/NetworkGhostPlayer.cpp",
    "src/Features/Demo/Demo.cpp",
    "src/Features/Demo/GhostLeaderboard.cpp",
    "src/Features/SeasonalASCII.cpp",
    "src/Features/Hud/PortalPlacement.cpp",
    "src/Features/Hud/Crosshair.cpp",
    "src/Features/Hud/Hud.cpp",
    "src/Features/Hud/Watermark.cpp",
    "src/Features/Hud/StrafeSyncHud.cpp",
    "src/Features/Hud/Toasts.cpp",
    "src/Features/Hud/InspectionHud.cpp",
    "src/Features/Hud/LPHud.cpp",
    "src/Features/Hud/PortalgunHud.cpp",
    "src/Features/Hud/StrafeHud.cpp",
    "src/Features/Hud/SpeedrunHud.cpp",
    "src/Features/Hud/AimPointHud.cpp",
    "src/Features/Hud/CheatWarn.cpp",
    "src/Features/Hud/Minimap.cpp",
    "src/Features/Hud/VelocityGraph.cpp",
    "src/Features/Hud/StrafeQuality.cpp",
    "src/Features/Hud/InputHud.cpp",
    "src/Features/Hud/VphysHud.cpp",
    "src/Features/Hud/ScrollSpeed.cpp",
    "src/Features/AutoSubmit.cpp",
    "src/Features/Stitcher.cpp",
    "src/Features/Cvars.cpp",
    "src/Features/PlayerTrace.cpp",
    "src/Features/EntityList.cpp",
    "src/Features/SegmentedTools.cpp",
    "src/Features/Routing/EntityInspector.cpp",
    "src/Features/Routing/Ruler.cpp",
    "src/Features/Routing/SeamshotFind.cpp",
    "src/Features/RNGManip.cpp",
    "src/Features/Tas/TasScript.cpp",
    "src/Features/Tas/TasTool.cpp",
    "src/Features/Tas/TasPlayer.cpp",
    "src/Features/Tas/TasServer.cpp",
    "src/Features/Tas/TasController.cpp",
    "src/Features/Tas/TasParser.cpp",
    "src/Features/Tas/TasTools/CheckTool.cpp",
    "src/Features/Tas/TasTools/AngleToolsUtils.cpp",
    "src/Features/Tas/TasTools/StrafeTool.cpp",
    "src/Features/Tas/TasTools/AbsoluteMoveTool.cpp",
    "src/Features/Tas/TasTools/SetAngleTool.cpp",
    "src/Features/Tas/TasTools/AutoAimTool.cpp",
    "src/Features/Tas/TasTools/AutoJumpTool.cpp",
    "src/Features/Tas/TasTools/DecelTool.cpp",
    "src/Features/Tas/TasTools/TasUtils.cpp",
    "src/Features/ReloadedFix.cpp",
    "src/Features/Pathmatch.cpp",
    "src/Features/Speedrun/Rules.cpp",
    "src/Features/Speedrun/SpeedrunTimer.cpp",
    "src/Features/Speedrun/CategoriesPreset.cpp",
    "src/Features/Speedrun/CategoryCreator.cpp",
    "src/Features/Speedrun/Categories.cpp",
    "src/Features/Session.cpp",
    "src/Features/Listener.cpp",
    "src/Features/OverlayRender.cpp",
    "src/Features/WorkshopList.cpp",
    "src/Features/AchievementTracker.cpp",
    "src/Features/PlacementScanner.cpp",
    "src/CrashHandler.cpp",
    "src/Utils.cpp",
    "src/Offsets.cpp",
    "src/Scheduler.cpp",
    "src/Modules/Surface.cpp",
    "src/Modules/Client.cpp",
    "src/Modules/EngineDemoRecorder.cpp",
    "src/Modules/EngineDemoPlayer.cpp",
    "src/Modules/Tier1.cpp",
    "src/Modules/Module.cpp",
    "src/Modules/Server.cpp",
    "src/Modules/VGui.cpp",
    "src/Modules/Console.cpp",
    "src/Modules/InputSystem.cpp",
    "src/Modules/FileSystem.cpp",
    "src/Modules/Engine.cpp",
    "src/Modules/Scheme.cpp",
    "src/Modules/MaterialSystem.cpp",
    "src/Variable.cpp",
    "src/Game.cpp",
    "src/Games/ThinkingWithTimeMachine.cpp",
    "src/Games/PortalStoriesMel.cpp",
    "src/Games/ApertureTag.cpp",
    "src/Games/PortalReloaded.cpp",
    "src/Games/Portal2.cpp",
    "src/SAR.cpp",
    "src/Interface.cpp",
    "src/Utils/lodepng.cpp",
    "src/Utils/SDK/KeyValues.cpp",
    "src/Utils/SDK/ServerPlugin.cpp",
    "src/Utils/SDK/MeshBuilder.cpp",
    "src/Utils/SDK/EntityEdict.cpp",
    "src/Utils/ed25519/seed.cpp",
    "src/Utils/ed25519/sha512.cpp",
    "src/Utils/ed25519/key_exchange.cpp",
    "src/Utils/ed25519/verify.cpp",
    "src/Utils/ed25519/add_scalar.cpp",
    "src/Utils/ed25519/keypair.cpp",
    "src/Utils/ed25519/sign.cpp",
    "src/Utils/ed25519/fe.cpp",
    "src/Utils/ed25519/ge.cpp",
    "src/Utils/ed25519/sc.cpp",
    "src/Utils/json11.cpp",
    "src/Utils/Memory.cpp",
    "src/Utils/Math.cpp",
    "src/Command.cpp",
};

const libssh2_srcs = &.{
    "deps/libssh2/src/channel.c",
    "deps/libssh2/src/comp.c",
    "deps/libssh2/src/crypt.c",
    "deps/libssh2/src/hostkey.c",
    "deps/libssh2/src/kex.c",
    "deps/libssh2/src/mac.c",
    "deps/libssh2/src/misc.c",
    "deps/libssh2/src/packet.c",
    "deps/libssh2/src/publickey.c",
    "deps/libssh2/src/scp.c",
    "deps/libssh2/src/session.c",
    "deps/libssh2/src/sftp.c",
    "deps/libssh2/src/userauth.c",
    "deps/libssh2/src/transport.c",
    "deps/libssh2/src/version.c",
    "deps/libssh2/src/knownhost.c",
    "deps/libssh2/src/agent.c",
    "deps/libssh2/src/mbedtls.c",
    "deps/libssh2/src/pem.c",
    "deps/libssh2/src/keepalive.c",
    "deps/libssh2/src/global.c",
    "deps/libssh2/src/blowfish.c",
    "deps/libssh2/src/bcrypt_pbkdf.c",
    "deps/libssh2/src/agent_win.c",
};

const mbedtls_srcs = &.{
    "deps/mbedtls/library/certs.c",
    "deps/mbedtls/library/pkcs11.c",
    "deps/mbedtls/library/x509.c",
    "deps/mbedtls/library/x509_create.c",
    "deps/mbedtls/library/x509_crl.c",
    "deps/mbedtls/library/x509_crt.c",
    "deps/mbedtls/library/x509_csr.c",
    "deps/mbedtls/library/x509write_crt.c",
    "deps/mbedtls/library/x509write_csr.c",
    "deps/mbedtls/library/debug.c",
    "deps/mbedtls/library/net_sockets.c",
    "deps/mbedtls/library/ssl_cache.c",
    "deps/mbedtls/library/ssl_ciphersuites.c",
    "deps/mbedtls/library/ssl_cli.c",
    "deps/mbedtls/library/ssl_cookie.c",
    "deps/mbedtls/library/ssl_msg.c",
    "deps/mbedtls/library/ssl_srv.c",
    "deps/mbedtls/library/ssl_ticket.c",
    "deps/mbedtls/library/ssl_tls13_keys.c",
    "deps/mbedtls/library/ssl_tls.c",
    "deps/mbedtls/library/aes.c",
    "deps/mbedtls/library/aesni.c",
    "deps/mbedtls/library/arc4.c",
    "deps/mbedtls/library/aria.c",
    "deps/mbedtls/library/asn1parse.c",
    "deps/mbedtls/library/asn1write.c",
    "deps/mbedtls/library/base64.c",
    "deps/mbedtls/library/bignum.c",
    "deps/mbedtls/library/blowfish.c",
    "deps/mbedtls/library/camellia.c",
    "deps/mbedtls/library/ccm.c",
    "deps/mbedtls/library/chacha20.c",
    "deps/mbedtls/library/chachapoly.c",
    "deps/mbedtls/library/cipher.c",
    "deps/mbedtls/library/cipher_wrap.c",
    "deps/mbedtls/library/cmac.c",
    "deps/mbedtls/library/ctr_drbg.c",
    "deps/mbedtls/library/des.c",
    "deps/mbedtls/library/dhm.c",
    "deps/mbedtls/library/ecdh.c",
    "deps/mbedtls/library/ecdsa.c",
    "deps/mbedtls/library/ecjpake.c",
    "deps/mbedtls/library/ecp.c",
    "deps/mbedtls/library/ecp_curves.c",
    "deps/mbedtls/library/entropy.c",
    "deps/mbedtls/library/entropy_poll.c",
    "deps/mbedtls/library/error.c",
    "deps/mbedtls/library/gcm.c",
    "deps/mbedtls/library/havege.c",
    "deps/mbedtls/library/hkdf.c",
    "deps/mbedtls/library/hmac_drbg.c",
    "deps/mbedtls/library/md2.c",
    "deps/mbedtls/library/md4.c",
    "deps/mbedtls/library/md5.c",
    "deps/mbedtls/library/md.c",
    "deps/mbedtls/library/memory_buffer_alloc.c",
    "deps/mbedtls/library/mps_reader.c",
    "deps/mbedtls/library/mps_trace.c",
    "deps/mbedtls/library/nist_kw.c",
    "deps/mbedtls/library/oid.c",
    "deps/mbedtls/library/padlock.c",
    "deps/mbedtls/library/pem.c",
    "deps/mbedtls/library/pk.c",
    "deps/mbedtls/library/pkcs12.c",
    "deps/mbedtls/library/pkcs5.c",
    "deps/mbedtls/library/pkparse.c",
    "deps/mbedtls/library/pk_wrap.c",
    "deps/mbedtls/library/pkwrite.c",
    "deps/mbedtls/library/platform.c",
    "deps/mbedtls/library/platform_util.c",
    "deps/mbedtls/library/poly1305.c",
    "deps/mbedtls/library/psa_crypto_aead.c",
    "deps/mbedtls/library/psa_crypto.c",
    "deps/mbedtls/library/psa_crypto_cipher.c",
    "deps/mbedtls/library/psa_crypto_client.c",
    "deps/mbedtls/library/psa_crypto_driver_wrappers.c",
    "deps/mbedtls/library/psa_crypto_ecp.c",
    "deps/mbedtls/library/psa_crypto_hash.c",
    "deps/mbedtls/library/psa_crypto_mac.c",
    "deps/mbedtls/library/psa_crypto_rsa.c",
    "deps/mbedtls/library/psa_crypto_se.c",
    "deps/mbedtls/library/psa_crypto_slot_management.c",
    "deps/mbedtls/library/psa_crypto_storage.c",
    "deps/mbedtls/library/psa_its_file.c",
    "deps/mbedtls/library/ripemd160.c",
    "deps/mbedtls/library/rsa.c",
    "deps/mbedtls/library/rsa_internal.c",
    "deps/mbedtls/library/sha1.c",
    "deps/mbedtls/library/sha256.c",
    "deps/mbedtls/library/sha512.c",
    "deps/mbedtls/library/threading.c",
    "deps/mbedtls/library/timing.c",
    "deps/mbedtls/library/version.c",
    "deps/mbedtls/library/version_features.c",
    "deps/mbedtls/library/xtea.c",
};

fn buildLibssh2(
    b: *std.Build,
    target: std.zig.CrossTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.CompileStep {
    const ret = b.addStaticLibrary(.{
        .name = "ssh2",
        .target = target,
        .optimize = optimize,
    });
    ret.addIncludePath("deps/libssh2/include");
    ret.addIncludePath("deps/mbedtls/include");
    ret.addIncludePath(dep_config_dir);
    ret.addCSourceFiles(libssh2_srcs, &.{});
    ret.linkLibrary(buildMbedtls(b, target, optimize));
    ret.linkLibC();

    ret.defineCMacro("LIBSSH2_MBEDTLS", null);
    if (target.isWindows()) {
        ret.defineCMacro("_CRT_SECURE_NO_DEPRECATE", "1");
        ret.defineCMacro("HAVE_LIBCRYPT32", null);
        ret.defineCMacro("HAVE_WINSOCK2_H", null);
        ret.defineCMacro("HAVE_IOCTLSOCKET", null);
        ret.defineCMacro("HAVE_SELECT", null);
        ret.defineCMacro("LIBSSH2_DH_GEX_NEW", "1");

        if (target.getAbi().isGnu()) {
            ret.defineCMacro("HAVE_UNISTD_H", null);
            ret.defineCMacro("HAVE_INTTYPES_H", null);
            ret.defineCMacro("HAVE_SYS_TIME_H", null);
            ret.defineCMacro("HAVE_GETTIMEOFDAY", null);
        }
    } else {
        ret.defineCMacro("HAVE_UNISTD_H", null);
        ret.defineCMacro("HAVE_INTTYPES_H", null);
        ret.defineCMacro("HAVE_STDLIB_H", null);
        ret.defineCMacro("HAVE_SYS_SELECT_H", null);
        ret.defineCMacro("HAVE_SYS_UIO_H", null);
        ret.defineCMacro("HAVE_SYS_SOCKET_H", null);
        ret.defineCMacro("HAVE_SYS_IOCTL_H", null);
        ret.defineCMacro("HAVE_SYS_TIME_H", null);
        ret.defineCMacro("HAVE_SYS_UN_H", null);
        ret.defineCMacro("HAVE_LONGLONG", null);
        ret.defineCMacro("HAVE_GETTIMEOFDAY", null);
        ret.defineCMacro("HAVE_INET_ADDR", null);
        ret.defineCMacro("HAVE_POLL", null);
        ret.defineCMacro("HAVE_SELECT", null);
        ret.defineCMacro("HAVE_SOCKET", null);
        ret.defineCMacro("HAVE_STRTOLL", null);
        ret.defineCMacro("HAVE_SNPRINTF", null);
        ret.defineCMacro("HAVE_O_NONBLOCK", null);
    }

    return ret;
}

fn buildMbedtls(
    b: *std.Build,
    target: std.zig.CrossTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.CompileStep {
    const ret = b.addStaticLibrary(.{
        .name = "ssh2",
        .target = target,
        .optimize = optimize,
    });
    ret.addIncludePath("deps/mbedtls/include");
    ret.addIncludePath("deps/mbedtls/library");
    ret.addCSourceFiles(mbedtls_srcs, &.{});
    ret.linkLibC();

    return ret;
}

const curl_sources = &.{
    "deps/curl/lib/hostcheck.c",
    "deps/curl/lib/curl_gethostname.c",
    "deps/curl/lib/strerror.c",
    "deps/curl/lib/strdup.c",
    "deps/curl/lib/asyn-ares.c",
    "deps/curl/lib/pop3.c",
    "deps/curl/lib/bufref.c",
    "deps/curl/lib/rename.c",
    "deps/curl/lib/nwlib.c",
    "deps/curl/lib/file.c",
    "deps/curl/lib/curl_gssapi.c",
    "deps/curl/lib/ldap.c",
    "deps/curl/lib/socketpair.c",
    "deps/curl/lib/system_win32.c",
    "deps/curl/lib/http_aws_sigv4.c",
    "deps/curl/lib/content_encoding.c",
    "deps/curl/lib/vquic/ngtcp2.c",
    "deps/curl/lib/vquic/quiche.c",
    "deps/curl/lib/vquic/vquic.c",
    "deps/curl/lib/ftp.c",
    "deps/curl/lib/curl_ntlm_wb.c",
    "deps/curl/lib/curl_ntlm_core.c",
    "deps/curl/lib/hostip.c",
    "deps/curl/lib/urlapi.c",
    "deps/curl/lib/curl_get_line.c",
    "deps/curl/lib/vtls/mesalink.c",
    "deps/curl/lib/vtls/mbedtls_threadlock.c",
    "deps/curl/lib/vtls/nss.c",
    "deps/curl/lib/vtls/gskit.c",
    "deps/curl/lib/vtls/wolfssl.c",
    "deps/curl/lib/vtls/keylog.c",
    "deps/curl/lib/vtls/rustls.c",
    "deps/curl/lib/vtls/vtls.c",
    "deps/curl/lib/vtls/gtls.c",
    "deps/curl/lib/vtls/schannel.c",
    "deps/curl/lib/vtls/schannel_verify.c",
    "deps/curl/lib/vtls/sectransp.c",
    "deps/curl/lib/vtls/openssl.c",
    "deps/curl/lib/vtls/mbedtls.c",
    "deps/curl/lib/vtls/bearssl.c",
    "deps/curl/lib/parsedate.c",
    "deps/curl/lib/sendf.c",
    "deps/curl/lib/altsvc.c",
    "deps/curl/lib/krb5.c",
    "deps/curl/lib/curl_rtmp.c",
    "deps/curl/lib/curl_ctype.c",
    "deps/curl/lib/inet_pton.c",
    "deps/curl/lib/pingpong.c",
    "deps/curl/lib/mime.c",
    "deps/curl/lib/vauth/krb5_gssapi.c",
    "deps/curl/lib/vauth/krb5_sspi.c",
    "deps/curl/lib/vauth/spnego_sspi.c",
    "deps/curl/lib/vauth/digest.c",
    "deps/curl/lib/vauth/ntlm_sspi.c",
    "deps/curl/lib/vauth/vauth.c",
    "deps/curl/lib/vauth/gsasl.c",
    "deps/curl/lib/vauth/cram.c",
    "deps/curl/lib/vauth/oauth2.c",
    "deps/curl/lib/vauth/digest_sspi.c",
    "deps/curl/lib/vauth/cleartext.c",
    "deps/curl/lib/vauth/spnego_gssapi.c",
    "deps/curl/lib/vauth/ntlm.c",
    "deps/curl/lib/version_win32.c",
    "deps/curl/lib/multi.c",
    "deps/curl/lib/http_ntlm.c",
    "deps/curl/lib/curl_sspi.c",
    "deps/curl/lib/md5.c",
    "deps/curl/lib/dict.c",
    "deps/curl/lib/http.c",
    "deps/curl/lib/curl_des.c",
    "deps/curl/lib/memdebug.c",
    "deps/curl/lib/non-ascii.c",
    "deps/curl/lib/transfer.c",
    "deps/curl/lib/inet_ntop.c",
    "deps/curl/lib/slist.c",
    "deps/curl/lib/http_negotiate.c",
    "deps/curl/lib/http_digest.c",
    "deps/curl/lib/vssh/wolfssh.c",
    "deps/curl/lib/vssh/libssh.c",
    "deps/curl/lib/vssh/libssh2.c",
    "deps/curl/lib/hsts.c",
    "deps/curl/lib/escape.c",
    "deps/curl/lib/hostsyn.c",
    "deps/curl/lib/speedcheck.c",
    "deps/curl/lib/asyn-thread.c",
    "deps/curl/lib/curl_addrinfo.c",
    "deps/curl/lib/nwos.c",
    "deps/curl/lib/tftp.c",
    "deps/curl/lib/version.c",
    "deps/curl/lib/rand.c",
    "deps/curl/lib/psl.c",
    "deps/curl/lib/imap.c",
    "deps/curl/lib/mqtt.c",
    "deps/curl/lib/share.c",
    "deps/curl/lib/doh.c",
    "deps/curl/lib/curl_range.c",
    "deps/curl/lib/openldap.c",
    "deps/curl/lib/getinfo.c",
    "deps/curl/lib/select.c",
    "deps/curl/lib/base64.c",
    "deps/curl/lib/curl_sasl.c",
    "deps/curl/lib/curl_endian.c",
    "deps/curl/lib/connect.c",
    "deps/curl/lib/fileinfo.c",
    "deps/curl/lib/telnet.c",
    "deps/curl/lib/x509asn1.c",
    "deps/curl/lib/conncache.c",
    "deps/curl/lib/strcase.c",
    "deps/curl/lib/if2ip.c",
    "deps/curl/lib/gopher.c",
    "deps/curl/lib/ftplistparser.c",
    "deps/curl/lib/setopt.c",
    "deps/curl/lib/idn_win32.c",
    "deps/curl/lib/strtoofft.c",
    "deps/curl/lib/hmac.c",
    "deps/curl/lib/getenv.c",
    "deps/curl/lib/smb.c",
    "deps/curl/lib/dotdot.c",
    "deps/curl/lib/curl_threads.c",
    "deps/curl/lib/md4.c",
    "deps/curl/lib/easygetopt.c",
    "deps/curl/lib/curl_fnmatch.c",
    "deps/curl/lib/sha256.c",
    "deps/curl/lib/cookie.c",
    "deps/curl/lib/amigaos.c",
    "deps/curl/lib/progress.c",
    "deps/curl/lib/nonblock.c",
    "deps/curl/lib/llist.c",
    "deps/curl/lib/hostip6.c",
    "deps/curl/lib/dynbuf.c",
    "deps/curl/lib/warnless.c",
    "deps/curl/lib/hostasyn.c",
    "deps/curl/lib/http_chunks.c",
    "deps/curl/lib/wildcard.c",
    "deps/curl/lib/strtok.c",
    "deps/curl/lib/curl_memrchr.c",
    "deps/curl/lib/rtsp.c",
    "deps/curl/lib/http2.c",
    "deps/curl/lib/socks.c",
    "deps/curl/lib/curl_path.c",
    "deps/curl/lib/curl_multibyte.c",
    "deps/curl/lib/http_proxy.c",
    "deps/curl/lib/formdata.c",
    "deps/curl/lib/netrc.c",
    "deps/curl/lib/socks_sspi.c",
    "deps/curl/lib/mprintf.c",
    "deps/curl/lib/easyoptions.c",
    "deps/curl/lib/easy.c",
    "deps/curl/lib/c-hyper.c",
    "deps/curl/lib/hostip4.c",
    "deps/curl/lib/timeval.c",
    "deps/curl/lib/smtp.c",
    "deps/curl/lib/splay.c",
    "deps/curl/lib/socks_gssapi.c",
    "deps/curl/lib/url.c",
    "deps/curl/lib/hash.c",
};

fn buildCurl(
    b: *std.Build,
    target: std.zig.CrossTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.CompileStep {
    const ret = b.addStaticLibrary(.{
        .name = "curl",
        .target = target,
        .optimize = optimize,
    });
    ret.addCSourceFiles(curl_sources, &.{});
    ret.addIncludePath("deps/curl/include");
    ret.addIncludePath("deps/curl/lib");
    ret.addIncludePath("deps/libssh2/include");
    ret.addIncludePath("deps/mbedtls/include");
    ret.addIncludePath("deps/zlib");
    ret.linkLibrary(buildLibssh2(b, target, optimize));
    ret.linkLibrary(buildZlib(b, target, optimize));
    ret.linkLibC();

    ret.defineCMacro("BUILDING_LIBCURL", null);

    // disables LDAP
    ret.defineCMacro("CURL_DISABLE_LDAP", "1");

    // disables LDAPS
    ret.defineCMacro("CURL_DISABLE_LDAPS", "1");

    // if mbedTLS is enabled
    ret.defineCMacro("USE_MBEDTLS", "1");

    // disables alt-svc
    // #undef CURL_DISABLE_ALTSVC

    // disables cookies support
    // #undef CURL_DISABLE_COOKIES

    // disables cryptographic authentication
    // #undef CURL_DISABLE_CRYPTO_AUTH

    // disables DICT
    ret.defineCMacro("CURL_DISABLE_DICT", "1");

    // disables DNS-over-HTTPS
    // #undef CURL_DISABLE_DOH

    // disables FILE
    ret.defineCMacro("CURL_DISABLE_FILE", "1");

    // disables FTP
    ret.defineCMacro("CURL_DISABLE_FTP", "1");

    // disables GOPHER
    ret.defineCMacro("CURL_DISABLE_GOPHER", "1");

    // disables HSTS support
    // #undef CURL_DISABLE_HSTS

    // disables HTTP
    // #undef CURL_DISABLE_HTTP

    // disables IMAP
    ret.defineCMacro("CURL_DISABLE_IMAP", "1");

    // disables --libcurl option from the curl tool
    // #undef CURL_DISABLE_LIBCURL_OPTION

    // disables MIME support
    // #undef CURL_DISABLE_MIME

    // disables MQTT
    ret.defineCMacro("CURL_DISABLE_MQTT", "1");

    // disables netrc parser
    // #undef CURL_DISABLE_NETRC

    // disables NTLM support
    // #undef CURL_DISABLE_NTLM

    // disables date parsing
    // #undef CURL_DISABLE_PARSEDATE

    // disables POP3
    ret.defineCMacro("CURL_DISABLE_POP3", "1");

    // disables built-in progress meter
    // #undef CURL_DISABLE_PROGRESS_METER

    // disables proxies
    // #undef CURL_DISABLE_PROXY

    // disables RTSP
    ret.defineCMacro("CURL_DISABLE_RTSP", "1");

    // disables SMB
    ret.defineCMacro("CURL_DISABLE_SMB", "1");

    // disables SMTP
    ret.defineCMacro("CURL_DISABLE_SMTP", "1");

    // disables use of socketpair for curl_multi_poll
    // #undef CURL_DISABLE_SOCKETPAIR

    // disables TELNET
    ret.defineCMacro("CURL_DISABLE_TELNET", "1");

    // disables TFTP
    ret.defineCMacro("CURL_DISABLE_TFTP", "1");

    // disables verbose strings
    // #undef CURL_DISABLE_VERBOSE_STRINGS

    // Define to 1 if you have the `ssh2' library (-lssh2).
    ret.defineCMacro("HAVE_LIBSSH2", "1");

    // Define to 1 if you have the <libssh2.h> header file.
    ret.defineCMacro("HAVE_LIBSSH2_H", "1");

    // if zlib is available
    ret.defineCMacro("HAVE_LIBZ", "1");

    // if you have the zlib.h header file
    ret.defineCMacro("HAVE_ZLIB_H", "1");

    if (target.isWindows()) {
        // Define if you want to enable WIN32 threaded DNS lookup
        //ret.defineCMacro("USE_THREADS_WIN32", "1");

        return ret;
    }

    //ret.defineCMacro("libcurl_EXPORTS", null);

    //ret.defineCMacro("STDC_HEADERS", null);

    // when building libcurl itself
    // #undef BUILDING_LIBCURL

    // Location of default ca bundle
    // ret.defineCMacro("CURL_CA_BUNDLE", "\"/etc/ssl/certs/ca-certificates.crt\"");

    // define "1" to use built-in ca store of TLS backend
    // #undef CURL_CA_FALLBACK

    // Location of default ca path
    // ret.defineCMacro("CURL_CA_PATH", "\"/etc/ssl/certs\"");

    // to make a symbol visible
    ret.defineCMacro("CURL_EXTERN_SYMBOL", "__attribute__ ((__visibility__ (\"default\"))");
    // Ensure using CURL_EXTERN_SYMBOL is possible
    //#ifndef CURL_EXTERN_SYMBOL
    //ret.defineCMacro("CURL_EXTERN_SYMBOL
    //#endif

    // Allow SMB to work on Windows
    // #undef USE_WIN32_CRYPTO

    // Use Windows LDAP implementation
    // #undef USE_WIN32_LDAP

    // your Entropy Gathering Daemon socket pathname
    // #undef EGD_SOCKET

    // Define if you want to enable IPv6 support
    if (!target.isDarwin())
        ret.defineCMacro("ENABLE_IPV6", "1");

    // Define to 1 if you have the alarm function.
    ret.defineCMacro("HAVE_ALARM", "1");

    // Define to 1 if you have the <alloca.h> header file.
    ret.defineCMacro("HAVE_ALLOCA_H", "1");

    // Define to 1 if you have the <arpa/inet.h> header file.
    ret.defineCMacro("HAVE_ARPA_INET_H", "1");

    // Define to 1 if you have the <arpa/tftp.h> header file.
    ret.defineCMacro("HAVE_ARPA_TFTP_H", "1");

    // Define to 1 if you have the <assert.h> header file.
    ret.defineCMacro("HAVE_ASSERT_H", "1");

    // Define to 1 if you have the `basename' function.
    ret.defineCMacro("HAVE_BASENAME", "1");

    // Define to 1 if bool is an available type.
    ret.defineCMacro("HAVE_BOOL_T", "1");

    // Define to 1 if you have the __builtin_available function.
    ret.defineCMacro("HAVE_BUILTIN_AVAILABLE", "1");

    // Define to 1 if you have the clock_gettime function and monotonic timer.
    ret.defineCMacro("HAVE_CLOCK_GETTIME_MONOTONIC", "1");

    // Define to 1 if you have the `closesocket' function.
    // #undef HAVE_CLOSESOCKET

    // Define to 1 if you have the `CRYPTO_cleanup_all_ex_data' function.
    // #undef HAVE_CRYPTO_CLEANUP_ALL_EX_DATA

    // Define to 1 if you have the <dlfcn.h> header file.
    ret.defineCMacro("HAVE_DLFCN_H", "1");

    // Define to 1 if you have the <errno.h> header file.
    ret.defineCMacro("HAVE_ERRNO_H", "1");

    // Define to 1 if you have the fcntl function.
    ret.defineCMacro("HAVE_FCNTL", "1");

    // Define to 1 if you have the <fcntl.h> header file.
    ret.defineCMacro("HAVE_FCNTL_H", "1");

    // Define to 1 if you have a working fcntl O_NONBLOCK function.
    ret.defineCMacro("HAVE_FCNTL_O_NONBLOCK", "1");

    // Define to 1 if you have the freeaddrinfo function.
    ret.defineCMacro("HAVE_FREEADDRINFO", "1");

    // Define to 1 if you have the ftruncate function.
    ret.defineCMacro("HAVE_FTRUNCATE", "1");

    // Define to 1 if you have a working getaddrinfo function.
    ret.defineCMacro("HAVE_GETADDRINFO", "1");

    // Define to 1 if you have the `geteuid' function.
    ret.defineCMacro("HAVE_GETEUID", "1");

    // Define to 1 if you have the `getppid' function.
    ret.defineCMacro("HAVE_GETPPID", "1");

    // Define to 1 if you have the gethostbyname function.
    ret.defineCMacro("HAVE_GETHOSTBYNAME", "1");

    // Define to 1 if you have the gethostbyname_r function.
    if (!target.isDarwin())
        ret.defineCMacro("HAVE_GETHOSTBYNAME_R", "1");

    // gethostbyname_r() takes 3 args
    // #undef HAVE_GETHOSTBYNAME_R_3

    // gethostbyname_r() takes 5 args
    // #undef HAVE_GETHOSTBYNAME_R_5

    // gethostbyname_r() takes 6 args
    ret.defineCMacro("HAVE_GETHOSTBYNAME_R_6", "1");

    // Define to 1 if you have the gethostname function.
    ret.defineCMacro("HAVE_GETHOSTNAME", "1");

    // Define to 1 if you have a working getifaddrs function.
    // #undef HAVE_GETIFADDRS

    // Define to 1 if you have the `getpass_r' function.
    // #undef HAVE_GETPASS_R

    // Define to 1 if you have the `getppid' function.
    ret.defineCMacro("HAVE_GETPPID", "1");

    // Define to 1 if you have the `getprotobyname' function.
    ret.defineCMacro("HAVE_GETPROTOBYNAME", "1");

    // Define to 1 if you have the `getpeername' function.
    ret.defineCMacro("HAVE_GETPEERNAME", "1");

    // Define to 1 if you have the `getsockname' function.
    ret.defineCMacro("HAVE_GETSOCKNAME", "1");

    // Define to 1 if you have the `if_nametoindex' function.
    ret.defineCMacro("HAVE_IF_NAMETOINDEX", "1");

    // Define to 1 if you have the `getpwuid' function.
    ret.defineCMacro("HAVE_GETPWUID", "1");

    // Define to 1 if you have the `getpwuid_r' function.
    ret.defineCMacro("HAVE_GETPWUID_R", "1");

    // Define to 1 if you have the `getrlimit' function.
    ret.defineCMacro("HAVE_GETRLIMIT", "1");

    // Define to 1 if you have the `gettimeofday' function.
    ret.defineCMacro("HAVE_GETTIMEOFDAY", "1");

    // Define to 1 if you have a working glibc-style strerror_r function.
    // #undef HAVE_GLIBC_STRERROR_R

    // Define to 1 if you have a working gmtime_r function.
    ret.defineCMacro("HAVE_GMTIME_R", "1");

    // if you have the gssapi libraries
    // #undef HAVE_GSSAPI

    // Define to 1 if you have the <gssapi/gssapi_generic.h> header file.
    // #undef HAVE_GSSAPI_GSSAPI_GENERIC_H

    // Define to 1 if you have the <gssapi/gssapi.h> header file.
    // #undef HAVE_GSSAPI_GSSAPI_H

    // Define to 1 if you have the <gssapi/gssapi_krb5.h> header file.
    // #undef HAVE_GSSAPI_GSSAPI_KRB5_H

    // if you have the GNU gssapi libraries
    // #undef HAVE_GSSGNU

    // if you have the Heimdal gssapi libraries
    // #undef HAVE_GSSHEIMDAL

    // if you have the MIT gssapi libraries
    // #undef HAVE_GSSMIT

    // Define to 1 if you have the `idna_strerror' function.
    // #undef HAVE_IDNA_STRERROR

    // Define to 1 if you have the `idn_free' function.
    // #undef HAVE_IDN_FREE

    // Define to 1 if you have the <idn-free.h> header file.
    // #undef HAVE_IDN_FREE_H

    // Define to 1 if you have the <ifaddrs.h> header file.
    ret.defineCMacro("HAVE_IFADDRS_H", "1");

    // Define to 1 if you have the `inet_addr' function.
    ret.defineCMacro("HAVE_INET_ADDR", "1");

    // Define to 1 if you have a IPv6 capable working inet_ntop function.
    // #undef HAVE_INET_NTOP

    // Define to 1 if you have a IPv6 capable working inet_pton function.
    ret.defineCMacro("HAVE_INET_PTON", "1");

    // Define to 1 if symbol `sa_family_t' exists
    ret.defineCMacro("HAVE_SA_FAMILY_T", "1");

    // Define to 1 if symbol `ADDRESS_FAMILY' exists
    // #undef HAVE_ADDRESS_FAMILY

    // Define to 1 if you have the <inttypes.h> header file.
    ret.defineCMacro("HAVE_INTTYPES_H", "1");

    // Define to 1 if you have the ioctl function.
    ret.defineCMacro("HAVE_IOCTL", "1");

    // Define to 1 if you have the ioctlsocket function.
    // #undef HAVE_IOCTLSOCKET

    // Define to 1 if you have the IoctlSocket camel case function.
    // #undef HAVE_IOCTLSOCKET_CAMEL

    // Define to 1 if you have a working IoctlSocket camel case FIONBIO function.

    // #undef HAVE_IOCTLSOCKET_CAMEL_FIONBIO

    // Define to 1 if you have a working ioctlsocket FIONBIO function.
    // #undef HAVE_IOCTLSOCKET_FIONBIO

    // Define to 1 if you have a working ioctl FIONBIO function.
    ret.defineCMacro("HAVE_IOCTL_FIONBIO", "1");

    // Define to 1 if you have a working ioctl SIOCGIFADDR function.
    ret.defineCMacro("HAVE_IOCTL_SIOCGIFADDR", "1");

    // Define to 1 if you have the <io.h> header file.
    // #undef HAVE_IO_H

    // if you have the Kerberos4 libraries (including -ldes)
    // #undef HAVE_KRB4

    // Define to 1 if you have the `krb_get_our_ip_for_realm' function.
    // #undef HAVE_KRB_GET_OUR_IP_FOR_REALM

    // Define to 1 if you have the <krb.h> header file.
    // #undef HAVE_KRB_H

    // Define to 1 if you have the lber.h header file.
    // #undef HAVE_LBER_H

    // Define to 1 if you have the ldapssl.h header file.
    // #undef HAVE_LDAPSSL_H

    // Define to 1 if you have the ldap.h header file.
    // #undef HAVE_LDAP_H

    // Use LDAPS implementation
    // #undef HAVE_LDAP_SSL

    // Define to 1 if you have the ldap_ssl.h header file.
    // #undef HAVE_LDAP_SSL_H

    // Define to 1 if you have the `ldap_url_parse' function.
    ret.defineCMacro("HAVE_LDAP_URL_PARSE", "1");

    // Define to 1 if you have the <libgen.h> header file.
    ret.defineCMacro("HAVE_LIBGEN_H", "1");

    // Define to 1 if you have the `idn2' library (-lidn2).
    // #undef HAVE_LIBIDN2

    // Define to 1 if you have the idn2.h header file.
    ret.defineCMacro("HAVE_IDN2_H", "1");

    // Define to 1 if you have the `resolv' library (-lresolv).
    // #undef HAVE_LIBRESOLV

    // Define to 1 if you have the `resolve' library (-lresolve).
    // #undef HAVE_LIBRESOLVE

    // Define to 1 if you have the `socket' library (-lsocket).
    // #undef HAVE_LIBSOCKET

    // if brotli is available
    // #undef HAVE_BROTLI

    // if zstd is available
    // #undef HAVE_ZSTD

    // if your compiler supports LL
    ret.defineCMacro("HAVE_LL", "1");

    // Define to 1 if you have the <locale.h> header file.
    ret.defineCMacro("HAVE_LOCALE_H", "1");

    // Define to 1 if you have a working localtime_r function.
    ret.defineCMacro("HAVE_LOCALTIME_R", "1");

    // Define to 1 if the compiler supports the 'long long' data type.
    ret.defineCMacro("HAVE_LONGLONG", "1");

    // Define to 1 if you have the malloc.h header file.
    ret.defineCMacro("HAVE_MALLOC_H", "1");

    // Define to 1 if you have the <memory.h> header file.
    ret.defineCMacro("HAVE_MEMORY_H", "1");

    // Define to 1 if you have the MSG_NOSIGNAL flag.
    if (!target.isDarwin())
        ret.defineCMacro("HAVE_MSG_NOSIGNAL", "1");

    // Define to 1 if you have the <netdb.h> header file.
    ret.defineCMacro("HAVE_NETDB_H", "1");

    // Define to 1 if you have the <netinet/in.h> header file.
    ret.defineCMacro("HAVE_NETINET_IN_H", "1");

    // Define to 1 if you have the <netinet/tcp.h> header file.
    ret.defineCMacro("HAVE_NETINET_TCP_H", "1");

    // Define to 1 if you have the <linux/tcp.h> header file.
    if (target.isLinux())
        ret.defineCMacro("HAVE_LINUX_TCP_H", "1");

    // Define to 1 if you have the <net/if.h> header file.
    ret.defineCMacro("HAVE_NET_IF_H", "1");

    // Define to 1 if NI_WITHSCOPEID exists and works.
    // #undef HAVE_NI_WITHSCOPEID

    // if you have an old MIT gssapi library, lacking GSS_C_NT_HOSTBASED_SERVICE
    // #undef HAVE_OLD_GSSMIT

    // Define to 1 if you have the <pem.h> header file.
    // #undef HAVE_PEM_H

    // Define to 1 if you have the `pipe' function.
    ret.defineCMacro("HAVE_PIPE", "1");

    // Define to 1 if you have a working poll function.
    ret.defineCMacro("HAVE_POLL", "1");

    // If you have a fine poll
    ret.defineCMacro("HAVE_POLL_FINE", "1");

    // Define to 1 if you have the <poll.h> header file.
    ret.defineCMacro("HAVE_POLL_H", "1");

    // Define to 1 if you have a working POSIX-style strerror_r function.
    ret.defineCMacro("HAVE_POSIX_STRERROR_R", "1");

    // Define to 1 if you have the <pthread.h> header file
    ret.defineCMacro("HAVE_PTHREAD_H", "1");

    // Define to 1 if you have the <pwd.h> header file.
    ret.defineCMacro("HAVE_PWD_H", "1");

    // Define to 1 if you have the `RAND_egd' function.
    // #undef HAVE_RAND_EGD

    // Define to 1 if you have the `RAND_screen' function.
    // #undef HAVE_RAND_SCREEN

    // Define to 1 if you have the `RAND_status' function.
    // #undef HAVE_RAND_STATUS

    // Define to 1 if you have the recv function.
    ret.defineCMacro("HAVE_RECV", "1");

    // Define to 1 if you have the recvfrom function.
    // #undef HAVE_RECVFROM

    // Define to 1 if you have the select function.
    ret.defineCMacro("HAVE_SELECT", "1");

    // Define to 1 if you have the send function.
    ret.defineCMacro("HAVE_SEND", "1");

    // Define to 1 if you have the 'fsetxattr' function.
    ret.defineCMacro("HAVE_FSETXATTR", "1");

    // fsetxattr() takes 5 args
    ret.defineCMacro("HAVE_FSETXATTR_5", "1");

    // fsetxattr() takes 6 args
    // #undef HAVE_FSETXATTR_6

    // Define to 1 if you have the <setjmp.h> header file.
    ret.defineCMacro("HAVE_SETJMP_H", "1");

    // Define to 1 if you have the `setlocale' function.
    ret.defineCMacro("HAVE_SETLOCALE", "1");

    // Define to 1 if you have the `setmode' function.
    // #undef HAVE_SETMODE

    // Define to 1 if you have the `setrlimit' function.
    ret.defineCMacro("HAVE_SETRLIMIT", "1");

    // Define to 1 if you have the setsockopt function.
    ret.defineCMacro("HAVE_SETSOCKOPT", "1");

    // Define to 1 if you have a working setsockopt SO_NONBLOCK function.
    // #undef HAVE_SETSOCKOPT_SO_NONBLOCK

    // Define to 1 if you have the sigaction function.
    ret.defineCMacro("HAVE_SIGACTION", "1");

    // Define to 1 if you have the siginterrupt function.
    ret.defineCMacro("HAVE_SIGINTERRUPT", "1");

    // Define to 1 if you have the signal function.
    ret.defineCMacro("HAVE_SIGNAL", "1");

    // Define to 1 if you have the <signal.h> header file.
    ret.defineCMacro("HAVE_SIGNAL_H", "1");

    // Define to 1 if you have the sigsetjmp function or macro.
    ret.defineCMacro("HAVE_SIGSETJMP", "1");

    // Define to 1 if struct sockaddr_in6 has the sin6_scope_id member
    ret.defineCMacro("HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID", "1");

    // Define to 1 if you have the `socket' function.
    ret.defineCMacro("HAVE_SOCKET", "1");

    // Define to 1 if you have the <stdbool.h> header file.
    ret.defineCMacro("HAVE_STDBOOL_H", "1");

    // Define to 1 if you have the <stdint.h> header file.
    ret.defineCMacro("HAVE_STDINT_H", "1");

    // Define to 1 if you have the <stdio.h> header file.
    ret.defineCMacro("HAVE_STDIO_H", "1");

    // Define to 1 if you have the <stdlib.h> header file.
    ret.defineCMacro("HAVE_STDLIB_H", "1");

    // Define to 1 if you have the strcasecmp function.
    ret.defineCMacro("HAVE_STRCASECMP", "1");

    // Define to 1 if you have the strcasestr function.
    // #undef HAVE_STRCASESTR

    // Define to 1 if you have the strcmpi function.
    // #undef HAVE_STRCMPI

    // Define to 1 if you have the strdup function.
    ret.defineCMacro("HAVE_STRDUP", "1");

    // Define to 1 if you have the strerror_r function.
    ret.defineCMacro("HAVE_STRERROR_R", "1");

    // Define to 1 if you have the stricmp function.
    // #undef HAVE_STRICMP

    // Define to 1 if you have the <strings.h> header file.
    ret.defineCMacro("HAVE_STRINGS_H", "1");

    // Define to 1 if you have the <string.h> header file.
    ret.defineCMacro("HAVE_STRING_H", "1");

    // Define to 1 if you have the strncmpi function.
    // #undef HAVE_STRNCMPI

    // Define to 1 if you have the strnicmp function.
    // #undef HAVE_STRNICMP

    // Define to 1 if you have the <stropts.h> header file.
    // #undef HAVE_STROPTS_H

    // Define to 1 if you have the strstr function.
    ret.defineCMacro("HAVE_STRSTR", "1");

    // Define to 1 if you have the strtok_r function.
    ret.defineCMacro("HAVE_STRTOK_R", "1");

    // Define to 1 if you have the strtoll function.
    ret.defineCMacro("HAVE_STRTOLL", "1");

    // if struct sockaddr_storage is defined
    ret.defineCMacro("HAVE_STRUCT_SOCKADDR_STORAGE", "1");

    // Define to 1 if you have the timeval struct.
    ret.defineCMacro("HAVE_STRUCT_TIMEVAL", "1");

    // Define to 1 if you have the <sys/filio.h> header file.
    // #undef HAVE_SYS_FILIO_H

    // Define to 1 if you have the <sys/ioctl.h> header file.
    ret.defineCMacro("HAVE_SYS_IOCTL_H", "1");

    // Define to 1 if you have the <sys/param.h> header file.
    ret.defineCMacro("HAVE_SYS_PARAM_H", "1");

    // Define to 1 if you have the <sys/poll.h> header file.
    ret.defineCMacro("HAVE_SYS_POLL_H", "1");

    // Define to 1 if you have the <sys/resource.h> header file.
    ret.defineCMacro("HAVE_SYS_RESOURCE_H", "1");

    // Define to 1 if you have the <sys/select.h> header file.
    ret.defineCMacro("HAVE_SYS_SELECT_H", "1");

    // Define to 1 if you have the <sys/socket.h> header file.
    ret.defineCMacro("HAVE_SYS_SOCKET_H", "1");

    // Define to 1 if you have the <sys/sockio.h> header file.
    // #undef HAVE_SYS_SOCKIO_H

    // Define to 1 if you have the <sys/stat.h> header file.
    ret.defineCMacro("HAVE_SYS_STAT_H", "1");

    // Define to 1 if you have the <sys/time.h> header file.
    ret.defineCMacro("HAVE_SYS_TIME_H", "1");

    // Define to 1 if you have the <sys/types.h> header file.
    ret.defineCMacro("HAVE_SYS_TYPES_H", "1");

    // Define to 1 if you have the <sys/uio.h> header file.
    ret.defineCMacro("HAVE_SYS_UIO_H", "1");

    // Define to 1 if you have the <sys/un.h> header file.
    ret.defineCMacro("HAVE_SYS_UN_H", "1");

    // Define to 1 if you have the <sys/utime.h> header file.
    // #undef HAVE_SYS_UTIME_H

    // Define to 1 if you have the <termios.h> header file.
    ret.defineCMacro("HAVE_TERMIOS_H", "1");

    // Define to 1 if you have the <termio.h> header file.
    ret.defineCMacro("HAVE_TERMIO_H", "1");

    // Define to 1 if you have the <time.h> header file.
    ret.defineCMacro("HAVE_TIME_H", "1");

    // Define to 1 if you have the <tld.h> header file.
    // #undef HAVE_TLD_H

    // Define to 1 if you have the `tld_strerror' function.
    // #undef HAVE_TLD_STRERROR

    // Define to 1 if you have the `uname' function.
    ret.defineCMacro("HAVE_UNAME", "1");

    // Define to 1 if you have the <unistd.h> header file.
    ret.defineCMacro("HAVE_UNISTD_H", "1");

    // Define to 1 if you have the `utime' function.
    ret.defineCMacro("HAVE_UTIME", "1");

    // Define to 1 if you have the `utimes' function.
    ret.defineCMacro("HAVE_UTIMES", "1");

    // Define to 1 if you have the <utime.h> header file.
    ret.defineCMacro("HAVE_UTIME_H", "1");

    // Define to 1 if compiler supports C99 variadic macro style.
    ret.defineCMacro("HAVE_VARIADIC_MACROS_C99", "1");

    // Define to 1 if compiler supports old gcc variadic macro style.
    ret.defineCMacro("HAVE_VARIADIC_MACROS_GCC", "1");

    // Define to 1 if you have the winber.h header file.
    // #undef HAVE_WINBER_H

    // Define to 1 if you have the windows.h header file.
    // #undef HAVE_WINDOWS_H

    // Define to 1 if you have the winldap.h header file.
    // #undef HAVE_WINLDAP_H

    // Define to 1 if you have the winsock2.h header file.
    // #undef HAVE_WINSOCK2_H

    // Define this symbol if your OS supports changing the contents of argv
    // #undef HAVE_WRITABLE_ARGV

    // Define to 1 if you have the writev function.
    // #undef HAVE_WRITEV

    // Define to 1 if you have the ws2tcpip.h header file.
    // #undef HAVE_WS2TCPIP_H

    // Define to 1 if you have the <x509.h> header file.
    // #undef HAVE_X509_H

    // Define if you have the <process.h> header file.
    // #undef HAVE_PROCESS_H

    // Define to the sub-directory in which libtool stores uninstalled libraries.

    // #undef LT_OBJDIR

    // If you lack a fine basename() prototype
    // #undef NEED_BASENAME_PROTO

    // Define to 1 if you need the lber.h header file even with ldap.h
    // #undef NEED_LBER_H

    // Define to 1 if you need the malloc.h header file even with stdlib.h
    // #undef NEED_MALLOC_H

    // Define to 1 if _REENTRANT preprocessor symbol must be defined.
    // #undef NEED_REENTRANT

    // cpu-machine-OS
    ret.defineCMacro("OS", "\"Linux\"");

    // Name of package
    // #undef PACKAGE

    // Define to the address where bug reports for this package should be sent.
    // #undef PACKAGE_BUGREPORT

    // Define to the full name of this package.
    // #undef PACKAGE_NAME

    // Define to the full name and version of this package.
    // #undef PACKAGE_STRING

    // Define to the one symbol short name of this package.
    // #undef PACKAGE_TARNAME

    // Define to the version of this package.
    // #undef PACKAGE_VERSION

    // a suitable file to read random data from
    ret.defineCMacro("RANDOM_FILE", "\"/dev/urandom\"");

    // Define to the type of arg 1 for recvfrom.
    // #undef RECVFROM_TYPE_ARG1

    // Define to the type pointed by arg 2 for recvfrom.
    // #undef RECVFROM_TYPE_ARG2

    // Define to 1 if the type pointed by arg 2 for recvfrom is void.
    // #undef RECVFROM_TYPE_ARG2_IS_VOID

    // Define to the type of arg 3 for recvfrom.
    // #undef RECVFROM_TYPE_ARG3

    // Define to the type of arg 4 for recvfrom.
    // #undef RECVFROM_TYPE_ARG4

    // Define to the type pointed by arg 5 for recvfrom.
    // #undef RECVFROM_TYPE_ARG5

    // Define to 1 if the type pointed by arg 5 for recvfrom is void.
    // #undef RECVFROM_TYPE_ARG5_IS_VOID

    // Define to the type pointed by arg 6 for recvfrom.
    // #undef RECVFROM_TYPE_ARG6

    // Define to 1 if the type pointed by arg 6 for recvfrom is void.
    // #undef RECVFROM_TYPE_ARG6_IS_VOID

    // Define to the function return type for recvfrom.
    // #undef RECVFROM_TYPE_RETV

    // Define to the type of arg 1 for recv.
    ret.defineCMacro("RECV_TYPE_ARG1", "int");

    // Define to the type of arg 2 for recv.
    ret.defineCMacro("RECV_TYPE_ARG2", "void *");

    // Define to the type of arg 3 for recv.
    ret.defineCMacro("RECV_TYPE_ARG3", "size_t");

    // Define to the type of arg 4 for recv.
    ret.defineCMacro("RECV_TYPE_ARG4", "int");

    // Define to the function return type for recv.
    ret.defineCMacro("RECV_TYPE_RETV", "ssize_t");

    // Define to the type qualifier of arg 5 for select.
    // #undef SELECT_QUAL_ARG5

    // Define to the type of arg 1 for select.
    // #undef SELECT_TYPE_ARG1

    // Define to the type of args 2, 3 and 4 for select.
    // #undef SELECT_TYPE_ARG234

    // Define to the type of arg 5 for select.
    // #undef SELECT_TYPE_ARG5

    // Define to the function return type for select.
    // #undef SELECT_TYPE_RETV

    // Define to the type qualifier of arg 2 for send.
    ret.defineCMacro("SEND_QUAL_ARG2", "const");

    // Define to the type of arg 1 for send.
    ret.defineCMacro("SEND_TYPE_ARG1", "int");

    // Define to the type of arg 2 for send.
    ret.defineCMacro("SEND_TYPE_ARG2", "void *");

    // Define to the type of arg 3 for send.
    ret.defineCMacro("SEND_TYPE_ARG3", "size_t");

    // Define to the type of arg 4 for send.
    ret.defineCMacro("SEND_TYPE_ARG4", "int");

    // Define to the function return type for send.
    ret.defineCMacro("SEND_TYPE_RETV", "ssize_t");

    // Note: SIZEOF_* variables are fetched with CMake through check_type_size().
    // As per CMake documentation on CheckTypeSize, C preprocessor code is
    // generated by CMake into SIZEOF_*_CODE. This is what we use in the
    // following statements.
    //
    // Reference: https://cmake.org/cmake/help/latest/module/CheckTypeSize.html

    // The size of `int', as computed by sizeof.
    ret.defineCMacro("SIZEOF_INT", "4");

    // The size of `short', as computed by sizeof.
    ret.defineCMacro("SIZEOF_SHORT", "2");

    // The size of `long', as computed by sizeof.
    ret.defineCMacro("SIZEOF_LONG", "8");

    // The size of `off_t', as computed by sizeof.
    ret.defineCMacro("SIZEOF_OFF_T", "8");

    // The size of `curl_off_t', as computed by sizeof.
    ret.defineCMacro("SIZEOF_CURL_OFF_T", "8");

    // The size of `size_t', as computed by sizeof.
    ret.defineCMacro("SIZEOF_SIZE_T", "8");

    // The size of `time_t', as computed by sizeof.
    ret.defineCMacro("SIZEOF_TIME_T", "8");

    // Define to 1 if you have the ANSI C header files.
    ret.defineCMacro("STDC_HEADERS", "1");

    // Define to the type of arg 3 for strerror_r.
    // #undef STRERROR_R_TYPE_ARG3

    // Define to 1 if you can safely include both <sys/time.h> and <time.h>.
    ret.defineCMacro("TIME_WITH_SYS_TIME", "1");

    // Define if you want to enable c-ares support
    // #undef USE_ARES

    // Define if you want to enable POSIX threaded DNS lookup
    ret.defineCMacro("USE_THREADS_POSIX", "1");

    // if libSSH2 is in use
    ret.defineCMacro("USE_LIBSSH2", "1");

    // If you want to build curl with the built-in manual
    // #undef USE_MANUAL

    // if NSS is enabled
    // #undef USE_NSS

    // if you have the PK11_CreateManagedGenericObject function
    // #undef HAVE_PK11_CREATEMANAGEDGENERICOBJECT

    // if you want to use OpenLDAP code instead of legacy ldap implementation
    // #undef USE_OPENLDAP

    // to enable NGHTTP2
    // #undef USE_NGHTTP2

    // to enable NGTCP2
    // #undef USE_NGTCP2

    // to enable NGHTTP3
    // #undef USE_NGHTTP3

    // to enable quiche
    // #undef USE_QUICHE

    // Define to 1 if you have the quiche_conn_set_qlog_fd function.
    // #undef HAVE_QUICHE_CONN_SET_QLOG_FD

    // if Unix domain sockets are enabled
    ret.defineCMacro("USE_UNIX_SOCKETS", null);

    // Define to 1 if you are building a Windows target with large file support.
    // #undef USE_WIN32_LARGE_FILES

    // to enable SSPI support
    // #undef USE_WINDOWS_SSPI

    // to enable Windows SSL
    // #undef USE_SCHANNEL

    // enable multiple SSL backends
    // #undef CURL_WITH_MULTI_SSL

    // Define to 1 if using yaSSL in OpenSSL compatibility mode.
    // #undef USE_YASSLEMUL

    // Version number of package
    // #undef VERSION

    // Define to 1 if OS is AIX.
    //#ifndef _ALL_SOURCE
    //#  undef _ALL_SOURCE
    //#endif

    // Number of bits in a file offset, on hosts where this is settable.
    ret.defineCMacro("_FILE_OFFSET_BITS", "64");

    // Define for large files, on AIX-style hosts.
    // #undef _LARGE_FILES

    // define this if you need it to compile thread-safe code
    // #undef _THREAD_SAFE

    // Define to empty if `const' does not conform to ANSI C.
    // #undef const

    // Type to use in place of in_addr_t when system does not provide it.
    // #undef in_addr_t

    // Define to `__inline__' or `__inline' if that's what the C compiler
    // calls it, or to nothing if 'inline' is not supported under any name.
    //#ifndef __cplusplus
    //#undef inline
    //#endif

    // Define to `unsigned int' if <sys/types.h> does not define.
    // #undef size_t

    // the signed version of size_t
    // #undef ssize_t

    // Define to 1 if you have the mach_absolute_time function.
    // #undef HAVE_MACH_ABSOLUTE_TIME

    // to enable Windows IDN
    // #undef USE_WIN32_IDN

    // to make the compiler know the prototypes of Windows IDN APIs
    // #undef WANT_IDN_PROTOTYPES

    return ret;
}

const zlib_srcs = &.{
    "deps/zlib/adler32.c",
    "deps/zlib/compress.c",
    "deps/zlib/crc32.c",
    "deps/zlib/deflate.c",
    "deps/zlib/gzclose.c",
    "deps/zlib/gzlib.c",
    "deps/zlib/gzread.c",
    "deps/zlib/gzwrite.c",
    "deps/zlib/inflate.c",
    "deps/zlib/infback.c",
    "deps/zlib/inftrees.c",
    "deps/zlib/inffast.c",
    "deps/zlib/trees.c",
    "deps/zlib/uncompr.c",
    "deps/zlib/zutil.c",
};

fn buildZlib(
    b: *std.Build,
    target: std.zig.CrossTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.CompileStep {
    const ret = b.addStaticLibrary(.{
        .name = "z",
        .target = target,
        .optimize = optimize,
    });
    ret.linkLibC();
    ret.addCSourceFiles(zlib_srcs, &.{"-std=c89"});
    return ret;
}

const sfml_sources = .{
    "deps/SFML/src/SFML/System/Thread.cpp",
    "deps/SFML/src/SFML/System/FileInputStream.cpp",
    "deps/SFML/src/SFML/System/MemoryInputStream.cpp",
    "deps/SFML/src/SFML/System/Err.cpp",
    "deps/SFML/src/SFML/System/Lock.cpp",
    "deps/SFML/src/SFML/System/String.cpp",
    "deps/SFML/src/SFML/System/Mutex.cpp",
    "deps/SFML/src/SFML/System/Sleep.cpp",
    "deps/SFML/src/SFML/System/Time.cpp",
    "deps/SFML/src/SFML/System/ThreadLocal.cpp",
    "deps/SFML/src/SFML/System/Clock.cpp",
    "deps/SFML/src/SFML/Network/Socket.cpp",
    "deps/SFML/src/SFML/Network/UdpSocket.cpp",
    "deps/SFML/src/SFML/Network/TcpListener.cpp",
    "deps/SFML/src/SFML/Network/Packet.cpp",
    "deps/SFML/src/SFML/Network/Ftp.cpp",
    "deps/SFML/src/SFML/Network/Http.cpp",
    "deps/SFML/src/SFML/Network/TcpSocket.cpp",
    "deps/SFML/src/SFML/Network/SocketSelector.cpp",
    "deps/SFML/src/SFML/Network/IpAddress.cpp",
};

const sfml_lin_sources = .{
    "deps/SFML/src/SFML/System/Unix/MutexImpl.cpp",
    "deps/SFML/src/SFML/System/Unix/ClockImpl.cpp",
    "deps/SFML/src/SFML/System/Unix/ThreadImpl.cpp",
    "deps/SFML/src/SFML/System/Unix/ThreadLocalImpl.cpp",
    "deps/SFML/src/SFML/System/Unix/SleepImpl.cpp",
    "deps/SFML/src/SFML/Network/Unix/SocketImpl.cpp",
};

const sfml_win_sources = .{
    "deps/SFML/src/SFML/System/Win32/MutexImpl.cpp",
    "deps/SFML/src/SFML/System/Win32/ClockImpl.cpp",
    "deps/SFML/src/SFML/System/Win32/ThreadImpl.cpp",
    "deps/SFML/src/SFML/System/Win32/ThreadLocalImpl.cpp",
    "deps/SFML/src/SFML/System/Win32/SleepImpl.cpp",
    "deps/SFML/src/SFML/Network/Win32/SocketImpl.cpp",
};

fn buildSfml(
    b: *std.Build,
    target: std.zig.CrossTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.CompileStep {
    const ret = b.addStaticLibrary(.{
        .name = "SFML",
        .target = target,
        .optimize = optimize,
    });
    ret.addIncludePath("deps/SFML/include");
    ret.addIncludePath("deps/SFML/src");
    if (target.isWindows()) ret.defineCMacro("_WIN32", null);
    ret.defineCMacro("SFML_NETWORK_EXPORTS", null);
    ret.defineCMacro("SFML_SYSTEM_EXPORTS", null);
    ret.linkLibC();
    ret.linkLibCpp();
    const sources: []const []const u8 = switch (target.getOs().tag) {
        .linux => &(sfml_sources ++ sfml_lin_sources),
        .windows => &(sfml_sources ++ sfml_win_sources),
        else => @panic("unsupported target"),
    };
    ret.addCSourceFiles(sources, &.{
        "-std=c++17",
        "-fno-sanitize=undefined", // no idea
    });
    return ret;
}
