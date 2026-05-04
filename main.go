package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// ─── ANSI Colors ──────────────────────────────────────────────────────────────
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

// ─── Regex Patterns ───────────────────────────────────────────────────────────
var (
	reHTTPS      = regexp.MustCompile(`https://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+`)
	reHTTP       = regexp.MustCompile(`http://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+`)
	reIP         = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b(?::(?:6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{0,3}))?`)
	reFirebase   = regexp.MustCompile(`[a-zA-Z0-9\-]+\.firebaseio\.com|[a-zA-Z0-9\-]+\.firebaseapp\.com|firebase\.google\.com`)
	reSupabase   = regexp.MustCompile(`[a-zA-Z0-9\-]+\.supabase\.co`)
	reMongoAtlas = regexp.MustCompile(`mongodb\+srv://[^\s"'<>]+|mongodb://[^\s"'<>]+`)
	reMysql      = regexp.MustCompile(`(?i)mysql://[^\s"'<>]+|jdbc:mysql://[^\s"'<>]+`)
	reSQLite     = regexp.MustCompile(`(?i)[a-zA-Z0-9_\-/]+\.db\b|[a-zA-Z0-9_\-/]+\.sqlite\b`)
	reRealtime   = regexp.MustCompile(`(?i)realm://[^\s"'<>]+`)
	reRedis      = regexp.MustCompile(`redis://[^\s"'<>]+|rediss://[^\s"'<>]+`)
	reBase64     = regexp.MustCompile(`(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)`)
	reGmail      = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@gmail\.com`)
	reOutlook    = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@(?:outlook|hotmail|live)\.com`)
	reProton     = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@(?:protonmail|proton)\.(?:com|me)`)
	reYahoo      = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@yahoo\.com`)
	reCustomMail = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}`)
	reAPIKey     = regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]\s*["']?([A-Za-z0-9\-_]{20,})["']?`)
)

// ═════════════════════════════════════════════════════════════════════════════
// FALSE POSITIVE FILTER — LEVEL 1 + LEVEL 2
// ═════════════════════════════════════════════════════════════════════════════

// smaliKnownPrefixes — Level 2 filter
// All standard Android/JVM/Kotlin/library class descriptor prefixes
// that appear in smali but are 100% benign — not C2, not secrets.
// Organized by category. Add new entries here as you encounter new noise.
var smaliKnownPrefixes = []string{

	// ── 1. Core Android & AndroidX ───────────────────────────────────────────
	"Landroid/",              // core Android framework + telephony/gsm/* covered here via L1
	"Landroidx/",             // ALL androidx: appcompat, core, lifecycle, room, compose, media3...
	"Landroid/support/",      // old support library (pre-androidx)
	"Lcom/android/internal/", // AOSP internal framework
	"Lcom/android/mms/",      // AOSP MMS classes
	"Lcom/android/",          // rest of com.android.*
	"Ldalvik/",               // Dalvik VM annotations & internals

	// ── 2. Java Standard Library ─────────────────────────────────────────────
	"Ljava/",  // java.lang, java.io, java.util, java.net ...
	"Ljavax/", // javax.annotation, javax.net, javax.crypto, javax.inject ...
	"Lsun/",   // sun.* JVM internals
	"Lsunx/",
	"Ljdk/", // jdk.* internals

	// ── 3. Kotlin ────────────────────────────────────────────────────────────
	"Lkotlin/",  // kotlin stdlib, coroutines, reflect
	"Lkotlinx/", // kotlinx: coroutines, serialization, datetime, collections

	// ── 4. Google (catch-all — covers GMS, Firebase, Material, Gson,
	//              Guava, Protobuf, MLKit, ExoPlayer, Accompanist,
	//              Dagger/Hilt, ZXing, Play Core, Cronet, DataTransport,
	//              Recaptcha, Truth, and every other com.google.* SDK)
	// NOTE: All "Lcom/google/android/gms/sub/", "Lcom/google/firebase/sub/"
	//       entries are REDUNDANT — this single prefix swallows them all.
	"Lcom/google/",

	// ── 5. Networking ────────────────────────────────────────────────────────
	"Lokhttp3/",               // OkHttp v3
	"Lokio/",                  // Okio (I/O lib used by OkHttp/Retrofit)
	"Lretrofit2/",             // Retrofit 2
	"Lcom/squareup/",          // OkHttp v2, Okio, Retrofit 1, Picasso, Inject, LeakCanary, Wire
	"Lcom/androidnetworking/", // Fast Android Networking library
	"Lcom/koushikdutta/",      // AndroidAsync / Ion
	"Lorg/chromium/net/",      // Cronet — Google HTTP stack (also under com/google but keep explicit)
	"Lio/ktor/",               // Ktor — Kotlin HTTP client
	"Lorg/java_websocket/",    // Java-WebSocket lib
	"Lcom/neovisionaries/ws/", // nv-websocket-client
	"Lcom/datadog/android/",   // Datadog RUM / APM tracing

	// ── 6. DI / Architecture ─────────────────────────────────────────────────
	// NOTE: Dagger (com/google/dagger/, hilt/) covered by "Lcom/google/" above
	// These are non-Google DI frameworks:
	"Ldagger/",    // Dagger 2 root package (separate from com/google/dagger)
	"Lhilt/",      // Hilt generated code root (separate from com/google/dagger/hilt)
	"Lorg/koin/",  // Koin DI — Kotlin-first DI framework
	"Ltoothpick/", // Toothpick DI

	// ── 7. Image Loading ─────────────────────────────────────────────────────
	"Lcom/bumptech/glide/",             // Glide
	"Lcom/github/bumptech/",            // Glide alternate path
	"Lcoil/",                           // Coil
	"Lio/coil/",                        // Coil alternate path
	"Lcom/airbnb/lottie/",              // Lottie animations
	"Lcom/yalantis/ucrop/",             // uCrop image cropper
	"Lcom/theartofdev/edmodo/cropper/", // Android Image Cropper
	"Lcom/zhihu/matisse/",              // Matisse image picker
	"Lcom/github/chrisbanes/",          // PhotoView / TouchImageView

	// ── 8. Reactive ──────────────────────────────────────────────────────────
	"Lio/reactivex/",        // RxJava 2 + RxJava 3 root
	"Lorg/reactivestreams/", // Reactive Streams spec (used by RxJava)

	// ── 9. Serialization / Parsing ───────────────────────────────────────────
	"Lcom/fasterxml/jackson/", // Jackson JSON
	"Lorg/json/",              // Android's built-in JSON
	"Lorg/msgpack/",           // MessagePack
	"Lorg/w3c/dom/",           // W3C DOM parsers
	"Lorg/xml/",               // XML parsers
	"Lorg/xmlpull/",           // XmlPull parser (Android internal)

	// ── 10. Apache Commons & HTTP ────────────────────────────────────────────
	"Lorg/apache/", // Apache Commons, HTTP components, logging, codec

	// ── 11. Security / Crypto ────────────────────────────────────────────────
	"Lorg/bouncycastle/",
	"Lorg/conscrypt/",

	// ── 12. Analytics / Crash Reporting / Attribution ────────────────────────
	// NOTE: Firebase Crashlytics / Analytics / Performance covered by "Lcom/google/"
	"Lcom/crashlytics/", // Legacy Fabric Crashlytics (pre-Google acquisition)
	"Lcom/mixpanel/",
	"Lcom/amplitude/",
	"Lcom/appsflyer/",
	"Lcom/adjust/sdk/",
	"Lcom/segment/analytics/", // Segment
	"Lcom/localytics/",        // Localytics
	"Lcom/flurry/",            // Flurry Analytics + Ads
	"Lcom/singular/sdk/",      // Singular attribution
	"Lcom/kochava/",           // Kochava attribution
	"Lcom/branch/",            // Branch.io deep links
	"Lio/branch/",             // Branch.io alternate package
	"Lcom/clevertap/",         // CleverTap
	"Lcom/moengage/",          // MoEngage
	"Lcom/moengageinapp/",     // MoEngage in-app messaging
	"Lcom/urbanairship/",      // Airship (Urban Airship) push
	"Lcom/leanplum/",          // Leanplum A/B + push
	"Lcom/tenjin/",            // Tenjin attribution
	"Lcom/onesignal/",         // OneSignal push notifications

	// ── 13. Push / Engagement / CRM ──────────────────────────────────────────
	// NOTE: FCM covered by "Lcom/google/"
	"Lcom/braze/",  // Braze (formerly Appboy)
	"Lcom/appboy/", // Braze legacy prefix
	"Lbo/app/",     // Braze internal generated package

	// ── 14. Ads Networks ─────────────────────────────────────────────────────
	// NOTE: AdMob covered by "Lcom/google/"
	"Lcom/unity3d/ads/", // Unity Ads
	"Lcom/chartboost/",  // Chartboost
	"Lcom/applovin/",    // AppLovin MAX
	"Lcom/ironsource/",  // IronSource (now Unity LevelPlay)
	"Lcom/vungle/",      // Vungle / Liftoff Monetize
	"Lcom/inmobi/",      // InMobi
	"Lcom/mbridge/",     // Mintegral
	"Lcom/startapp/",    // StartApp
	"Lcom/tapjoy/",      // Tapjoy
	"Lnet/pubnative/",   // PubNative / HyprMX
	"Lcom/ogury/",       // Ogury

	// ── 15. Facebook SDK ─────────────────────────────────────────────────────
	"Lcom/facebook/", // Facebook Login, Share, Analytics, Ads, Fresco
	"Lbolts/",        // Bolts — Facebook async task lib

	// ── 16. Payment / FinTech ────────────────────────────────────────────────
	"Lcom/razorpay/",
	"Lcom/paytm/",
	"Lnet/one97/paytm/", // Paytm alternate package
	"Lcom/stripe/",
	"Lcom/braintreepayments/", // Braintree (PayPal)
	"Lcom/paypal/",
	"Lcom/phonepe/",
	"Lbharat/pe/", // BharatPe
	"Lcom/cashfree/",
	"Lcom/ccavenue/",

	// ── 17. Database / Storage / ORM ─────────────────────────────────────────
	// NOTE: Firebase Realtime DB / Firestore covered by "Lcom/google/"
	// NOTE: Room covered by "Landroidx/"
	"Lio/realm/",                // Realm (modern Java/Kotlin SDK package)
	"Lcom/couchbase/lite/",      // Couchbase Lite
	"Lnet/sqlcipher/",           // SQLCipher — encrypted SQLite
	"Lorg/greenrobot/greendao/", // GreenDAO ORM
	"Lio/objectbox/",            // ObjectBox DB
	"Lorg/hibernate/",           // Hibernate ORM (rare but seen)
	"Lcom/j256/ormlite/",        // ORMLite

	// ── 18. Logging ──────────────────────────────────────────────────────────
	"Ltimber/", // Timber root
	"Lch/qos/logback/",
	"Lorg/slf4j/",

	// ── 19. UI / Component Libraries ─────────────────────────────────────────
	"Lcom/airbnb/epoxy/",               // Epoxy RecyclerView adapter
	"Lcom/afollestad/materialdialogs/", // Material Dialogs
	"Lcom/github/ybq/",                 // SpinKit loading animations
	"Lcom/wang/avi/",                   // AVLoadingIndicatorView
	"Lcom/journeyapps/barcodescanner/", // ZXing Android Embedded
	"Lme/dm77/barcodescannerlib/",      // Barcode scanner lib
	"Les/dmoral/toasty/",               // Toasty — custom toast
	"Lcom/github/chrisbanes/",          // PhotoView

	// ── 20. Date / Time ──────────────────────────────────────────────────────
	"Lorg/threeten/", // ThreeTen-Backport core

	// ── 21. JetBrains / IntelliJ annotations ─────────────────────────────────
	"Lorg/intellij/",
	"Lorg/jetbrains/",
	"Lcom/intellij/",

	// ── 22. JVM / Bytecode Internals ─────────────────────────────────────────
	"Lorg/objectweb/", // ASM bytecode manipulation lib

	// ── 23. Testing (present in non-stripped / debug APKs) ───────────────────
	"Lorg/junit/",
	"Lorg/mockito/",
	"Lorg/robolectric/",
	"Lcom/squareup/leakcanary/", // LeakCanary — covered by squareup/ but explicit for clarity

	// ── 24. Third-party Utility / Device-Info / Permissions ──────────────────
	"Lcom/karumi/dexter/",             // Dexter — runtime permissions
	"Lgithub/nisrulz/easydeviceinfo/", // EasyDeviceInfo — device fingerprinting
	"Lme/everything/providers/",       // Android-Providers — calls/contacts/SMS reader
	"Lcom/pixplicity/easyprefs/",      // EasyPrefs — SharedPreferences wrapper
	"Lcom/github/tamir7/contacts/",    // Contacts reader library
	"Lfr/quentinklein/",               // Simple Location Tracker
	"Leu/amirs/",                      // JSON/utility lib
	"Lcom/klinker/android/",           // Klinker SMS / Talon
	"Lnet/yslibrary/",                 // Various Android utils

	// ── 25. Jakewharton misc ─────────────────────────────────────────────────
	"Lcom/jakewharton/", // Covers Timber, ThreeTenABP, RxBinding, Picasso, etc.
}

// isSmaliDescriptor — combined L1 + L2 filter
func isSmaliDescriptor(s string) bool {
	// L1: True smali class descriptor — starts with L, has 2+ slashes, ends with ;
	// e.g. Lcom/example/MyClass; — the ; terminator is mandatory in valid smali
	if strings.HasPrefix(s, "L") && strings.HasSuffix(s, ";") {
		slashes := strings.Count(s, "/")
		if slashes >= 2 {
			return true
		}
	}

	// L2: Known prefix list
	for _, prefix := range smaliKnownPrefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}

	// L3: Smali type descriptors — arrays, primitives
	// e.g. [B, [I, [Ljava/lang/String;
	if strings.HasPrefix(s, "[") {
		return true
	}

	// L4: Ends with ; — smali class reference terminator
	if strings.HasSuffix(s, ";") {
		return true
	}

	// L5: Looks like a package path (contains dots like com.example.thing)
	// but encoded — skip if >3 dot-separated segments all lowercase
	parts := strings.Split(s, ".")
	if len(parts) >= 3 {
		allLower := true
		for _, p := range parts {
			if len(p) == 0 {
				allLower = false
				break
			}
			for _, c := range p {
				if c >= 'A' && c <= 'Z' {
					allLower = false
					break
				}
			}
		}
		if allLower {
			return true
		}
	}

	return false
}

// ═════════════════════════════════════════════════════════════════════════════
// ENCODING DETECTION & DECODE
// ═════════════════════════════════════════════════════════════════════════════

func isUTF16LE(b []byte) bool {
	if len(b) < 4 || len(b)%2 != 0 {
		return false
	}
	if b[0] == 0xFF && b[1] == 0xFE {
		return true
	}
	nullOdd := 0
	for i := 1; i < len(b); i += 2 {
		if b[i] == 0x00 {
			nullOdd++
		}
	}
	return float64(nullOdd)/float64(len(b)/2) > 0.60
}

func decodeUTF16LE(b []byte) string {
	start := 0
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		start = 2
	}
	var sb strings.Builder
	for i := start; i+1 < len(b); i += 2 {
		r := rune(uint16(b[i]) | uint16(b[i+1])<<8)
		if r == 0 {
			continue
		}
		sb.WriteRune(r)
	}
	return strings.TrimSpace(sb.String())
}

func isUTF16BE(b []byte) bool {
	if len(b) < 4 || len(b)%2 != 0 {
		return false
	}
	if b[0] == 0xFE && b[1] == 0xFF {
		return true
	}
	nullEven := 0
	for i := 0; i < len(b); i += 2 {
		if b[i] == 0x00 {
			nullEven++
		}
	}
	return float64(nullEven)/float64(len(b)/2) > 0.60
}

func decodeUTF16BE(b []byte) string {
	start := 0
	if len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF {
		start = 2
	}
	var sb strings.Builder
	for i := start; i+1 < len(b); i += 2 {
		r := rune(uint16(b[i])<<8 | uint16(b[i+1]))
		if r == 0 {
			continue
		}
		sb.WriteRune(r)
	}
	return strings.TrimSpace(sb.String())
}

func isLatin1Printable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if (c >= 0x20 && c <= 0x7E) || (c >= 0xA0 && c <= 0xFF) {
			printable++
		}
	}
	return float64(printable)/float64(len(b)) > 0.85
}

func decodeLatin1(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		sb.WriteRune(rune(c))
	}
	return strings.TrimSpace(sb.String())
}

var windows1252Map = map[byte]rune{
	0x80: '€', 0x82: '‚', 0x83: 'ƒ', 0x84: '„', 0x85: '…',
	0x86: '†', 0x87: '‡', 0x88: 'ˆ', 0x89: '‰', 0x8A: 'Š',
	0x8B: '‹', 0x8C: 'Œ', 0x8E: 'Ž',
	0x91: '\u2018', 0x92: '\u2019',
	0x93: '\u201C', 0x94: '\u201D',
	0x95: '•', 0x96: '–', 0x97: '—',
	0x98: '˜', 0x99: '™', 0x9A: 'š', 0x9B: '›', 0x9C: 'œ',
	0x9E: 'ž', 0x9F: 'Ÿ',
}

func isWindows1252(b []byte) bool {
	hasW := false
	for _, c := range b {
		if c == 0x81 || c == 0x8D || c == 0x8F || c == 0x90 || c == 0x9D {
			return false
		}
		if c >= 0x80 && c <= 0x9F {
			hasW = true
		}
	}
	return hasW
}

func decodeWindows1252(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if r, ok := windows1252Map[c]; ok {
			sb.WriteRune(r)
		} else {
			sb.WriteRune(rune(c))
		}
	}
	return strings.TrimSpace(sb.String())
}

var koi8rMap [256]rune

func initKOI8R() {
	for i := 0; i < 128; i++ {
		koi8rMap[i] = rune(i)
	}
	cyrillic := []rune{
		'─', '│', '┌', '┐', '└', '┘', '├', '┤', '┬', '┴', '┼', '▀', '▄', '█', '▌', '▐',
		'░', '▒', '▓', '⌠', '■', '∙', '√', '≈', '≤', '≥', '\u00A0', '⌡', '°', '²', '·', '÷',
		'═', '║', '╒', 'ё', '╓', '╔', '╕', '╖', '╗', '╘', '╙', '╚', '╛', '╜', '╝', '╞',
		'╟', 'Ё', '╠', '╡', '╢', '╣', '╤', '╥', '╦', '╧', '╨', '╩', '╪', '╫', '╬', '©',
		'ю', 'а', 'б', 'ц', 'д', 'е', 'ф', 'г', 'х', 'и', 'й', 'к', 'л', 'м', 'н', 'о',
		'п', 'я', 'р', 'с', 'т', 'у', 'ж', 'в', 'ь', 'ы', 'з', 'ш', 'э', 'щ', 'ч', 'ъ',
		'Ю', 'А', 'Б', 'Ц', 'Д', 'Е', 'Ф', 'Г', 'Х', 'И', 'Й', 'К', 'Л', 'М', 'Н', 'О',
		'П', 'Я', 'Р', 'С', 'Т', 'У', 'Ж', 'В', 'Ь', 'Ы', 'З', 'Ш', 'Э', 'Щ', 'Ч', 'Ъ',
	}
	for i, r := range cyrillic {
		koi8rMap[0x80+i] = r
	}
}

func isKOI8R(b []byte) bool {
	cyrCount := 0
	for _, c := range b {
		if c >= 0xC0 {
			cyrCount++
		}
	}
	return len(b) > 0 && float64(cyrCount)/float64(len(b)) > 0.30
}

func decodeKOI8R(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		sb.WriteRune(koi8rMap[c])
	}
	return strings.TrimSpace(sb.String())
}

func isGB18030(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	i, gbPairs, total := 0, 0, 0
	for i < len(b) {
		c := b[i]
		if c >= 0x81 && c <= 0xFE && i+1 < len(b) {
			next := b[i+1]
			if (next >= 0x40 && next <= 0x7E) || (next >= 0x80 && next <= 0xFE) {
				gbPairs++
				total++
				i += 2
				continue
			}
		}
		total++
		i++
	}
	return total > 0 && float64(gbPairs)/float64(total) > 0.40
}

func decodeGB18030(b []byte) string {
	var sb strings.Builder
	i := 0
	for i < len(b) {
		c := b[i]
		if c < 0x80 {
			sb.WriteByte(c)
			i++
		} else if c >= 0x81 && c <= 0xFE && i+1 < len(b) {
			sb.WriteString(fmt.Sprintf("\\x%02x%02x", c, b[i+1]))
			i += 2
		} else {
			sb.WriteString(fmt.Sprintf("\\x%02x", c))
			i++
		}
	}
	return "[GB18030] " + strings.TrimSpace(sb.String())
}

func isEUCJP(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	i, eucPairs, total := 0, 0, 0
	for i < len(b) {
		c := b[i]
		if c >= 0xA1 && c <= 0xFE && i+1 < len(b) && b[i+1] >= 0xA1 && b[i+1] <= 0xFE {
			eucPairs++
			total++
			i += 2
			continue
		}
		if c == 0x8E && i+1 < len(b) && b[i+1] >= 0xA1 && b[i+1] <= 0xDF {
			eucPairs++
			total++
			i += 2
			continue
		}
		total++
		i++
	}
	return total > 0 && float64(eucPairs)/float64(total) > 0.35
}

func decodeEUCJP(b []byte) string {
	var sb strings.Builder
	i := 0
	for i < len(b) {
		c := b[i]
		if c < 0x80 {
			sb.WriteByte(c)
			i++
		} else if c >= 0xA1 && c <= 0xFE && i+1 < len(b) {
			sb.WriteString(fmt.Sprintf("\\x%02x%02x", c, b[i+1]))
			i += 2
		} else if c == 0x8E && i+1 < len(b) {
			sb.WriteString(fmt.Sprintf("\\x8E%02x", b[i+1]))
			i += 2
		} else {
			sb.WriteString(fmt.Sprintf("\\x%02x", c))
			i++
		}
	}
	return "[EUC-JP] " + strings.TrimSpace(sb.String())
}

func isSJIS(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	i, pairs, total := 0, 0, 0
	for i < len(b) {
		c := b[i]
		isLead := (c >= 0x81 && c <= 0x9F) || (c >= 0xE0 && c <= 0xFC)
		if isLead && i+1 < len(b) {
			trail := b[i+1]
			if (trail >= 0x40 && trail <= 0x7E) || (trail >= 0x80 && trail <= 0xFC) {
				pairs++
				total++
				i += 2
				continue
			}
		}
		total++
		i++
	}
	return total > 0 && float64(pairs)/float64(total) > 0.35
}

func decodeSJIS(b []byte) string {
	var sb strings.Builder
	i := 0
	for i < len(b) {
		c := b[i]
		if c < 0x80 {
			sb.WriteByte(c)
			i++
		} else if ((c >= 0x81 && c <= 0x9F) || (c >= 0xE0 && c <= 0xFC)) && i+1 < len(b) {
			sb.WriteString(fmt.Sprintf("\\x%02x%02x", c, b[i+1]))
			i += 2
		} else {
			sb.WriteString(fmt.Sprintf("\\x%02x", c))
			i++
		}
	}
	return "[SJIS] " + strings.TrimSpace(sb.String())
}

func hexDump(b []byte) string {
	limit := 32
	if len(b) < limit {
		limit = len(b)
	}
	var sb strings.Builder
	for i := 0; i < limit; i++ {
		sb.WriteString(fmt.Sprintf("%02x ", b[i]))
	}
	result := strings.TrimSpace(sb.String())
	if len(b) > 32 {
		result += " ..."
	}
	return fmt.Sprintf("[binary %d bytes] hex: %s", len(b), result)
}

func tryDecodeBase64(s string) string {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		decoded2, err2 := base64.RawStdEncoding.DecodeString(s)
		if err2 != nil {
			return ""
		}
		decoded = decoded2
	}
	if len(decoded) == 0 {
		return ""
	}

	// 1. UTF-8 / ASCII
	if utf8.Valid(decoded) {
		result := strings.TrimSpace(string(decoded))
		if len(result) > 0 {
			return "[UTF-8] " + result
		}
	}
	// 2. UTF-16 LE
	if isUTF16LE(decoded) {
		if r := decodeUTF16LE(decoded); r != "" {
			return "[UTF-16LE] " + r
		}
	}
	// 3. UTF-16 BE
	if isUTF16BE(decoded) {
		if r := decodeUTF16BE(decoded); r != "" {
			return "[UTF-16BE] " + r
		}
	}
	// 4. Windows-1252 (before Latin-1 — more specific)
	if isWindows1252(decoded) {
		return "[Windows-1252] " + decodeWindows1252(decoded)
	}
	// 5. ISO-8859-1 / Latin-1
	if isLatin1Printable(decoded) {
		return "[ISO-8859-1] " + decodeLatin1(decoded)
	}
	// 6. KOI8-R (Russian)
	if isKOI8R(decoded) {
		return "[KOI8-R] " + decodeKOI8R(decoded)
	}
	// 7. Shift-JIS (before EUC-JP — overlapping ranges)
	if isSJIS(decoded) {
		return decodeSJIS(decoded)
	}
	// 8. EUC-JP
	if isEUCJP(decoded) {
		return decodeEUCJP(decoded)
	}
	// 9. GB18030 / GBK (Simplified Chinese)
	if isGB18030(decoded) {
		return decodeGB18030(decoded)
	}
	// 10. Hex dump fallback
	return hexDump(decoded)
}

// ═════════════════════════════════════════════════════════════════════════════
// BANNER
// ═════════════════════════════════════════════════════════════════════════════

func printBanner() {
	banner := colorPurple + colorBold + `
 ██╗  ██╗██╗   ██╗███╗   ██╗████████╗    ███████╗███████╗██╗  ██╗██╗   ██╗
 ██║  ██║██║   ██║████╗  ██║╚══██╔══╝    ██╔════╝██╔════╝╚██╗██╔╝╚██╗ ██╔╝
 ███████║██║   ██║██╔██╗ ██║   ██║       ███████╗█████╗   ╚███╔╝  ╚████╔╝ 
 ██╔══██║██║   ██║██║╚██╗██║   ██║       ╚════██║██╔══╝   ██╔██╗   ╚██╔╝  
 ██║  ██║╚██████╔╝██║ ╚████║   ██║       ███████║███████╗██╔╝ ██╗   ██║   
 ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝       ╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝   
` + colorReset

	smali := colorCyan + colorBold + `
  ███████╗███╗   ███╗ █████╗ ██╗     ██╗
  ██╔════╝████╗ ████║██╔══██╗██║     ██║
  ███████╗██╔████╔██║███████║██║     ██║
  ╚════██║██║╚██╔╝██║██╔══██║██║     ██║
  ███████║██║ ╚═╝ ██║██║  ██║███████╗██║
  ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝
` + colorReset

	info := colorYellow + `
  ┌──────────────────────────────────────────────────────────────────┐
  │  APK Smali Forensics · IOC Hunter · C2 Detector · v3             │
  │  Base64 Multi-Encoding ·  DB Endpoint · Reload Mode              │
  │  Author : github.com/gigachad80                                  │        
  │  Reload : hunt-sexy-smali -reload <All_Smali_path> -b -ip ...    │
  └──────────────────────────────────────────────────────────────────┘
` + colorReset

	fmt.Println(banner + smali + info)
}

type scanMode int

const (
	modeBatch  scanMode = 1 // Collect all → then hunt (current behavior)
	modeStream scanMode = 2 // Walk + hunt simultaneously, no disk collection
)

// ═════════════════════════════════════════════════════════════════════════════
// SCAN MODE SELECTOR — Interactive prompt at startup
// ═════════════════════════════════════════════════════════════════════════════

func askScanMode() scanMode {
	fmt.Println(colorCyan + colorBold + `
  ╔═══════════════════════════════════════════════════════════════════════╗
  ║                    SELECT SCAN MODE                                   ║
  ╠══════╦════════════════════════════════════════════════════════════════╣
  ║  1   ║  BATCH MODE — Collect All Smali → Then Hunt                    ║
  ║      ║  • Copies ALL .smali files into "All_Smali/" folder first      ║
  ║      ║  • Each file gets original path header comment                 ║
  ║      ║  • Hunt runs after full collection                             ║
  ║      ║  • Supports -reload flag for re-hunting later                  ║
  ║      ║  • Best for: Small/Medium APKs, repeated analysis              ║
  ║      ║  • Disk usage: HIGH (all smali files copied)                   ║
  ║      ║  • Memory: LOW (one file at a time during hunt)                ║
  ╠══════╬════════════════════════════════════════════════════════════════╣
  ║  2   ║  STREAM MODE — Walk + Hunt Simultaneously                      ║
  ║      ║  • No "All_Smali/" folder created                              ║
  ║      ║  • Each file scanned in memory, discarded if no hits           ║
  ║      ║  • Only findings saved to disk (not smali files)               ║
  ║      ║  • Best for: Large APKs (100MB+), one-time scans               ║
  ║      ║  • Disk usage: ZERO (smali files never copied)                 ║
  ║      ║  • Memory: LOW (one file at a time, hit or skip)               ║
  ╚══════╩════════════════════════════════════════════════════════════════╝` + colorReset)

	fmt.Print(colorYellow + "\n  Select mode [1/2]: " + colorReset)

	var input string
	fmt.Scanln(&input)
	input = strings.TrimSpace(input)

	switch input {
	case "1":
		fmt.Println(colorGreen + "  [✔] Batch Mode selected — All_Smali folder will be created.\n" + colorReset)
		return modeBatch
	case "2":
		fmt.Println(colorGreen + "  [✔] Stream Mode selected — Zero disk footprint. Hunting on the fly. 🔥\n" + colorReset)
		return modeStream
	default:
		fmt.Println(colorYellow + "  [!] Invalid input — defaulting to Batch Mode." + colorReset)
		return modeBatch
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// STREAM HUNT — Walk + Hunt simultaneously, no disk collection
// ═════════════════════════════════════════════════════════════════════════════

func streamHunt(inputDir string, flags huntFlags) []Finding {
	var allFindings []Finding
	fileCount := 0
	hitCount := 0

	fmt.Println(colorBold + colorCyan + "\n[STREAM] Walking + Hunting simultaneously..." + colorReset)

	filepath.WalkDir(inputDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) != ".smali" {
			return nil
		}

		fileCount++
		// Hunt directly in memory — no copy to disk
		found := huntFile(path, flags)
		if len(found) > 0 {
			hitCount++
			rel, _ := filepath.Rel(inputDir, path)
			fmt.Printf(colorGreen+"  [HIT]"+colorReset+" %s — %d finding(s)\n", rel, len(found))
			allFindings = append(allFindings, found...)
		}
		return nil
	})

	fmt.Printf(colorCyan+"\n  Scanned: %d files | Hits: %d files\n"+colorReset, fileCount, hitCount)
	return allFindings
}

// ═════════════════════════════════════════════════════════════════════════════
// SMALI COLLECTOR
// ═════════════════════════════════════════════════════════════════════════════

func collectSmali(inputDir, outputDir string) ([]string, error) {
	allSmaliDir := filepath.Join(outputDir, "All_Smali")
	if err := os.MkdirAll(allSmaliDir, 0755); err != nil {
		return nil, fmt.Errorf("cannot create All_Smali dir: %w", err)
	}

	var collected []string
	counter := 0

	err := filepath.WalkDir(inputDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) != ".smali" {
			return nil
		}
		counter++
		rel, _ := filepath.Rel(inputDir, path)
		flatName := strings.ReplaceAll(rel, string(os.PathSeparator), "__")
		dstPath := filepath.Join(allSmaliDir, flatName)
		if err2 := copySmaliWithHeader(path, dstPath, rel); err2 != nil {
			fmt.Printf(colorYellow+"  [WARN] Could not copy %s: %v\n"+colorReset, path, err2)
			return nil
		}
		collected = append(collected, dstPath)
		fmt.Printf(colorGreen+"  [+] Collected"+colorReset+" %s\n", rel)
		return nil
	})

	fmt.Printf(colorCyan+"\n  Total Smali files collected: %d\n"+colorReset, counter)
	return collected, err
}

// reloadSmali — for -reload flag: scan existing All_Smali dir directly
func reloadSmali(allSmaliDir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(allSmaliDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.ToLower(filepath.Ext(path)) == ".smali" {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func copySmaliWithHeader(src, dst, origRelPath string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	header := fmt.Sprintf("# [HUNT_SEXY_SMALI] Original-Path: %s\n", origRelPath)
	if _, err := dstFile.WriteString(header); err != nil {
		return err
	}
	_, err = io.Copy(dstFile, srcFile)
	return err
}

// ═════════════════════════════════════════════════════════════════════════════
// HUNT ENGINE
// ═════════════════════════════════════════════════════════════════════════════

type huntFlags struct {
	HTTP        bool
	IP          bool
	Base64      bool
	Mail        bool
	FilterLevel int // 0=raw, 1=basic, 2=full — only used when Base64=true
}

type Finding struct {
	SourceFile string
	Category   string
	Value      string
	Decoded    string
}

// ── Interactive filter level selector ─────────────────────────────────────────
// Called when -b is set but -fl is not provided by user.
// Shows a menu, reads input, supports single (2) or multi (1,2) selection.
func askFilterLevel() int {
	fmt.Println(colorCyan + colorBold + `
  ╔══════════════════════════════════════════════════════════════════════╗
  ║           BASE64 FALSE POSITIVE FILTER — LEVEL SELECTOR              ║
  ╠══════╦═══════════════════════════════════════════════════════════════╣
  ║  FL  ║  What it does                                                 ║
  ╠══════╬═══════════════════════════════════════════════════════════════╣
  ║  0   ║  RAW — Zero filters. Everything passes through.               ║
  ║      ║  Use : Research mode, unknown/custom APKs, paranoid scan      ║
  ║      ║  Kills: Nothing. Expect thousands of hits.                    ║
  ╠══════╬═══════════════════════════════════════════════════════════════╣
  ║  1   ║  BASIC — Structural filters only (no prefix list)             ║
  ║      ║  Use : Less noise but won't skip unknown libraries            ║
  ║      ║  Kills:                                                       ║
  ║      ║   • Strings shorter than 20 chars                             ║
  ║      ║   • Strings with no +, =, or / (not real base64)              ║
  ║      ║   • Strings with 3+ slashes (path-like, not encoded data)     ║
  ║      ║   • Strings starting with # (resource IDs, hex colors)        ║
  ║      ║  Est. reduction: ~65% false positives                         ║
  ╠══════╬═══════════════════════════════════════════════════════════════╣
  ║  2   ║  FULL — FL1 + 60+ known library prefix filter                 ║
  ║      ║  Use : Standard malware analysis (RECOMMENDED)                ║
  ║      ║  Kills everything FL1 kills, PLUS class descriptors from:     ║
  ║      ║   • Android / AndroidX / Dalvik / AOSP internals              ║
  ║      ║   • Java stdlib / Kotlin / kotlinx                            ║
  ║      ║   • Google GMS / Firebase / Material / Gson / Guava           ║
  ║      ║   • OkHttp v2+v3 / Okio / Retrofit / AndroidNetworking        ║
  ║      ║   • RxJava 2+3 / ReactiveStreams                              ║
  ║      ║   • Glide / Picasso / Coil / Fresco (image loaders)           ║
  ║      ║   • Dagger / Facebook SDK / Bolts                             ║
  ║      ║   • Apache / BouncyCastle / Conscrypt                         ║
  ║      ║   • Crashlytics / Mixpanel / AppsFlyer / Adjust               ║
  ║      ║   • Timber / SLF4J / Logback                                  ║
  ║      ║   • JetBrains / IntelliJ annotations                          ║
  ║      ║   • Dexter / EasyDeviceInfo / Toasty / EasyPrefs              ║
  ║      ║   • Klinker SMS / Contacts / Location Tracker libs            ║
  ║      ║  Est. reduction: ~95-97% false positives                      ║
  ╚══════╩═══════════════════════════════════════════════════════════════╝` + colorReset)

	fmt.Print(colorYellow + "\n  Select level(s) [0 / 1 / 2 / or combo like 1,2]: " + colorReset)

	var input string
	fmt.Scanln(&input)
	input = strings.TrimSpace(input)

	// Parse — support single "2" or multi "1,2"
	// Multi-select: we take the MAX level (higher level includes lower)
	parts := strings.Split(input, ",")
	maxLevel := -1
	for _, p := range parts {
		p = strings.TrimSpace(p)
		switch p {
		case "0":
			if maxLevel < 0 {
				maxLevel = 0
			}
		case "1":
			if maxLevel < 1 {
				maxLevel = 1
			}
		case "2":
			if maxLevel < 2 {
				maxLevel = 2
			}
		}
	}

	if maxLevel == -1 {
		fmt.Println(colorYellow + "  [!] Invalid input — defaulting to FL2 (recommended)" + colorReset)
		maxLevel = 2
	}

	fmt.Printf(colorGreen+"\n  [✔] Filter Level FL%d selected — ", maxLevel)
	switch maxLevel {
	case 0:
		fmt.Println("Raw mode. No filters. Brace yourself. 🔥" + colorReset)
	case 1:
		fmt.Println("Basic structural filter. ~65% noise reduction." + colorReset)
	case 2:
		fmt.Println("Full library filter. ~95-97% noise reduction. 🎯" + colorReset)
	}
	fmt.Println()
	return maxLevel
}

func huntFile(path string, flags huntFlags) []Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	content := string(data)
	base := filepath.Base(path)
	var findings []Finding

	add := func(cat, val, decoded string) {
		findings = append(findings, Finding{
			SourceFile: base,
			Category:   cat,
			Value:      strings.TrimSpace(val),
			Decoded:    decoded,
		})
	}

	// ── HTTP / HTTPS + DB ──
	if flags.HTTP {
		for _, m := range reHTTPS.FindAllString(content, -1) {
			add("HTTPS_URL", m, "")
		}
		for _, m := range reHTTP.FindAllString(content, -1) {
			add("HTTP_URL", m, "")
		}
		for _, m := range reFirebase.FindAllString(content, -1) {
			add("FIREBASE", m, "")
		}
		for _, m := range reSupabase.FindAllString(content, -1) {
			add("SUPABASE", m, "")
		}
		for _, m := range reMongoAtlas.FindAllString(content, -1) {
			add("MONGODB", m, "")
		}
		for _, m := range reMysql.FindAllString(content, -1) {
			add("MYSQL_CONN", m, "")
		}
		for _, m := range reSQLite.FindAllString(content, -1) {
			add("SQLITE_DB", m, "")
		}
		for _, m := range reRealtime.FindAllString(content, -1) {
			add("REALM_DB", m, "")
		}
		for _, m := range reRedis.FindAllString(content, -1) {
			add("REDIS", m, "")
		}
		for _, m := range reAPIKey.FindAllString(content, -1) {
			add("API_KEY", m, "")
		}
	}

	// ── IP addresses (port 1-65535 validated) ──
	if flags.IP {
		for _, m := range reIP.FindAllString(content, -1) {
			add("IP_ADDRESS", m, "")
		}
	}

	// ── Base64 — filter level controlled ──
	if flags.Base64 {
		for _, m := range reBase64.FindAllString(content, -1) {

			// ── FL1: Basic structural filters ──────────────────────────────
			if flags.FilterLevel >= 1 {
				// Too short to be meaningful
				if len(m) < 20 {
					continue
				}
				// No base64 special chars → likely a plain identifier, not encoded data
				hasPlus := strings.Contains(m, "+")
				hasEquals := strings.Contains(m, "=")
				hasSlash := strings.Contains(m, "/")
				if !hasPlus && !hasEquals && !hasSlash {
					continue
				}
				// Too many slashes → it's a path, not base64
				if strings.Count(m, "/") >= 3 {
					continue
				}
				// Resource IDs / hex colors start with #
				if strings.HasPrefix(m, "#") {
					continue
				}
			}

			// ── FL2: Known library class descriptor filter ──────────────────
			if flags.FilterLevel >= 2 {
				if isSmaliDescriptor(m) {
					continue
				}
			}

			decoded := tryDecodeBase64(m)
			if decoded != "" {
				add("BASE64", m, decoded)
			}
		}
	}

	// ── Email addresses ──
	if flags.Mail {
		for _, m := range reGmail.FindAllString(content, -1) {
			add("MAIL_GMAIL", m, "")
		}
		for _, m := range reOutlook.FindAllString(content, -1) {
			add("MAIL_OUTLOOK", m, "")
		}
		for _, m := range reProton.FindAllString(content, -1) {
			add("MAIL_PROTON", m, "")
		}
		for _, m := range reYahoo.FindAllString(content, -1) {
			add("MAIL_YAHOO", m, "")
		}
		for _, m := range reCustomMail.FindAllString(content, -1) {
			if !isKnownMailProvider(m) {
				add("MAIL_CUSTOM", m, "")
			}
		}
	}

	return findings
}

func isKnownMailProvider(email string) bool {
	known := []string{
		"gmail.com", "outlook.com", "hotmail.com", "live.com",
		"protonmail.com", "proton.me", "yahoo.com",
	}
	low := strings.ToLower(email)
	for _, k := range known {
		if strings.HasSuffix(low, "@"+k) {
			return true
		}
	}
	return false
}

// ═════════════════════════════════════════════════════════════════════════════
// REPORT
// ═════════════════════════════════════════════════════════════════════════════

func saveFindings(findings []Finding, outputDir string) (string, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", err
	}
	ts := time.Now().Format("20060102_150405")
	outFile := filepath.Join(outputDir, fmt.Sprintf("HSS_findings_%s.txt", ts))

	f, err := os.Create(outFile)
	if err != nil {
		return "", err
	}
	defer f.Close()

	fmt.Fprintf(f, "# ═══════════════════════════════════════════════════════\n")
	fmt.Fprintf(f, "# HUNT SEXY SMALI v3 — IOC / Findings Report\n")
	fmt.Fprintf(f, "# Generated : %s\n", time.Now().Format(time.RFC1123))
	fmt.Fprintf(f, "# Total     : %d finding(s)\n", len(findings))
	fmt.Fprintf(f, "# ═══════════════════════════════════════════════════════\n\n")

	groups := make(map[string][]Finding)
	for _, fi := range findings {
		groups[fi.Category] = append(groups[fi.Category], fi)
	}

	catOrder := []string{
		"HTTPS_URL", "HTTP_URL",
		"FIREBASE", "SUPABASE", "MONGODB", "MYSQL_CONN", "SQLITE_DB", "REALM_DB", "REDIS",
		"API_KEY", "IP_ADDRESS", "BASE64",
		"MAIL_GMAIL", "MAIL_OUTLOOK", "MAIL_PROTON", "MAIL_YAHOO", "MAIL_CUSTOM",
	}

	for _, cat := range catOrder {
		items, ok := groups[cat]
		if !ok {
			continue
		}
		fmt.Fprintf(f, "## [%s] — %d finding(s)\n", cat, len(items))
		fmt.Fprintf(f, "%s\n", strings.Repeat("─", 60))
		seen := make(map[string]bool)
		for _, it := range items {
			if seen[it.Value] {
				continue
			}
			seen[it.Value] = true
			fmt.Fprintf(f, "  Source : %s\n", it.SourceFile)
			fmt.Fprintf(f, "  Value  : %s\n", it.Value)
			if it.Decoded != "" {
				fmt.Fprintf(f, "  Decoded: %s\n", it.Decoded)
			}
			fmt.Fprintf(f, "\n")
		}
	}

	return outFile, nil
}

// ═════════════════════════════════════════════════════════════════════════════
// MAIL
// ═════════════════════════════════════════════════════════════════════════════

// ═════════════════════════════════════════════════════════════════════════════
// SHARED HUNT RUNNER
// ═════════════════════════════════════════════════════════════════════════════

func runHunt(smaliFiles []string, flags huntFlags, outputPath string) {
	// Phase 2 — Hunt
	fmt.Println(colorBold + colorCyan + "\n[PHASE 2] Hunting IOCs in Smali files..." + colorReset)
	var allFindings []Finding
	for _, sf := range smaliFiles {
		found := huntFile(sf, flags)
		if len(found) > 0 {
			fmt.Printf(colorGreen+"  [HIT]"+colorReset+" %s — %d finding(s)\n", filepath.Base(sf), len(found))
			allFindings = append(allFindings, found...)
		}
	}

	if len(allFindings) == 0 {
		fmt.Println(colorYellow + "\n[~] No IOCs found with the selected flags." + colorReset)
		return
	}

	// Phase 3 — Summary
	fmt.Printf(colorBold + colorPurple + "\n[PHASE 3] Summary of Findings\n" + colorReset)
	catCounts := make(map[string]int)
	for _, fi := range allFindings {
		catCounts[fi.Category]++
	}
	// Print in order
	catOrder := []string{
		"HTTPS_URL", "HTTP_URL", "FIREBASE", "SUPABASE", "MONGODB",
		"MYSQL_CONN", "SQLITE_DB", "REALM_DB", "REDIS", "API_KEY",
		"IP_ADDRESS", "BASE64",
		"MAIL_GMAIL", "MAIL_OUTLOOK", "MAIL_PROTON", "MAIL_YAHOO", "MAIL_CUSTOM",
	}
	for _, cat := range catOrder {
		if c, ok := catCounts[cat]; ok {
			fmt.Printf("  %-20s → %d\n", cat, c)
		}
	}

	// Phase 4 — Save
	fmt.Println(colorBold + colorCyan + "\n[PHASE 4] Saving findings..." + colorReset)
	outFile, err := saveFindings(allFindings, outputPath)
	if err != nil {
		fmt.Printf(colorRed+"[!] Could not save findings: %v\n"+colorReset, err)
		return
	}
	fmt.Printf(colorGreen+"  [✔] Report saved: %s\n"+colorReset, outFile)

}

// ═════════════════════════════════════════════════════════════════════════════
// MAIN
// ═════════════════════════════════════════════════════════════════════════════

func main() {
	initKOI8R()
	printBanner()

	inputPath := flag.String("i", "", "Input path of decompiled APK folder")
	outputPath := flag.String("o", "HSS_Output", "Output folder for findings and All_Smali")
	reloadPath := flag.String("reload", "", "Re-hunt on existing All_Smali folder (skip collection)")
	flagHTTP := flag.Bool("h", false, "Hunt HTTP/HTTPS URLs + Firebase/Supabase/Mongo/MySQL/Realm DB endpoints + Redis")
	flagIP := flag.Bool("ip", false, "Hunt IP addresses (port 1-65535 validated)")
	flagBase64 := flag.Bool("b", false, "Hunt and decode Base64 (multi-encoding aware)")
	flagMail := flag.Bool("m", false, "Hunt email addresses (Gmail, Proton, Outlook, Yahoo, custom)")
	flagFL := flag.Int("fl", -1, "Base64 filter level: 0=raw 1=basic 2=full (asked interactively if -b used without -fl)")

	flag.Parse()

	// ── Validate: need either -i or -reload ──
	if *inputPath == "" && *reloadPath == "" {
		fmt.Println(colorRed + "[!] Error: provide -i <apk_path> OR -reload <All_Smali_path>" + colorReset)
		flag.Usage()
		os.Exit(1)
	}

	// ── Default: no flags → enable all ──
	if !*flagHTTP && !*flagIP && !*flagBase64 && !*flagMail {
		fmt.Println(colorYellow + "[!] No hunt flags set — defaulting to ALL (-h -ip -b -m)" + colorReset)
		*flagHTTP = true
		*flagIP = true
		*flagBase64 = true
		*flagMail = true
	}

	// ── Resolve filter level ──
	// Rules:
	//   -b NOT set        → FilterLevel irrelevant, set to -1 (skip all base64)
	//   -b set, -fl set   → use provided -fl value directly
	//   -b set, -fl not set → ask interactively with menu
	resolvedFL := -1
	if *flagBase64 {
		if *flagFL >= 0 && *flagFL <= 2 {
			// User provided -fl explicitly — use it, no prompt
			resolvedFL = *flagFL
			flLabel := map[int]string{0: "Raw (no filters)", 1: "Basic structural", 2: "Full library filter"}
			fmt.Printf(colorGreen+"  [FL] Filter level FL%d applied: %s\n"+colorReset, resolvedFL, flLabel[resolvedFL])
		} else {
			// -b is set but -fl not provided → show interactive menu
			resolvedFL = askFilterLevel()
		}
	}

	flags := huntFlags{
		HTTP:        *flagHTTP,
		IP:          *flagIP,
		Base64:      *flagBase64,
		Mail:        *flagMail,
		FilterLevel: resolvedFL,
	}

	// ════════════════════════════════
	// MODE A: -reload (skip collect)
	// ════════════════════════════════
	if *reloadPath != "" {
		if _, err := os.Stat(*reloadPath); os.IsNotExist(err) {
			fmt.Printf(colorRed+"[!] Reload path does not exist: %s\n"+colorReset, *reloadPath)
			os.Exit(1)
		}

		fmt.Printf(colorBold+colorCyan+"\n[RELOAD MODE] Re-hunting: %s\n"+colorReset, *reloadPath)

		fmt.Println(colorYellow + "  [!] -reload uses Batch Mode only (Stream Mode skipped — no All_Smali exists)" + colorReset)
		smaliFiles, err := reloadSmali(*reloadPath)
		if err != nil || len(smaliFiles) == 0 {
			fmt.Println(colorYellow + "[!] No .smali files found in reload path." + colorReset)
			os.Exit(0)
		}
		fmt.Printf(colorCyan+"  Found %d smali files to re-hunt\n"+colorReset, len(smaliFiles))

		reloadOutput := filepath.Join(filepath.Dir(*reloadPath), "HSS_Reload_Output")
		runHunt(smaliFiles, flags, reloadOutput) // ← yeh missing thi
		fmt.Println(colorPurple + colorBold + "\n[✔] Reload hunt complete. Stay sexy. 🔥\n" + colorReset)
		return
	}

	// ════════════════════════════════
	// MODE B: -i (ask scan mode first)
	// ════════════════════════════════
	if _, err := os.Stat(*inputPath); os.IsNotExist(err) {
		fmt.Printf(colorRed+"[!] Input path does not exist: %s\n"+colorReset, *inputPath)
		os.Exit(1)
	}

	selectedMode := askScanMode()

	switch selectedMode {

	case modeBatch:
		fmt.Println(colorBold + colorCyan + "\n[PHASE 1] Collecting .smali files..." + colorReset)
		smaliFiles, err := collectSmali(*inputPath, *outputPath)
		if err != nil {
			fmt.Printf(colorRed+"[!] Error during collection: %v\n"+colorReset, err)
			os.Exit(1)
		}
		if len(smaliFiles) == 0 {
			fmt.Println(colorYellow + "[!] No .smali files found." + colorReset)
			os.Exit(0)
		}
		runHunt(smaliFiles, flags, *outputPath)

	case modeStream:
		allFindings := streamHunt(*inputPath, flags)
		if len(allFindings) == 0 {
			fmt.Println(colorYellow + "\n[~] No IOCs found." + colorReset)
			os.Exit(0)
		}
		// Summary
		fmt.Printf(colorBold + colorPurple + "\n[PHASE 3] Summary of Findings\n" + colorReset)
		catCounts := make(map[string]int)
		for _, fi := range allFindings {
			catCounts[fi.Category]++
		}
		catOrder := []string{
			"HTTPS_URL", "HTTP_URL", "FIREBASE", "SUPABASE", "MONGODB",
			"MYSQL_CONN", "SQLITE_DB", "REALM_DB", "REDIS", "API_KEY",
			"IP_ADDRESS", "BASE64",
			"MAIL_GMAIL", "MAIL_OUTLOOK", "MAIL_PROTON", "MAIL_YAHOO", "MAIL_CUSTOM",
		}
		for _, cat := range catOrder {
			if c, ok := catCounts[cat]; ok {
				fmt.Printf("  %-20s → %d\n", cat, c)
			}
		}
		// Save
		fmt.Println(colorBold + colorCyan + "\n[PHASE 4] Saving findings..." + colorReset)
		outFile, err := saveFindings(allFindings, *outputPath)
		if err != nil {
			fmt.Printf(colorRed+"[!] Could not save: %v\n"+colorReset, err)
			os.Exit(1)
		}
		fmt.Printf(colorGreen+"  [✔] Report saved: %s\n"+colorReset, outFile)

	}

	fmt.Println(colorPurple + colorBold + "\n[✔] Hunt complete. Stay sexy. 🔥\n" + colorReset)
}
