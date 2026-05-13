

type NetlifyContext = {
    next: () => Promise<Response>;
};

const SITELINE_WEBSITE_KEY = process.env.SITELINE_WEBSITE_KEY;
const SITELINE_DEBUG = false;
const SITELINE_ENDPOINT = 'https://api.siteline.ai/v1/intake/pageview'

const DEFAULT_SDK_NAME = '@siteline/core';
const DEFAULT_SDK_VERSION = '1.0.9';
const DEFAULT_INTEGRATION_TYPE = 'netlify-edge';


type SitelineConfig = {
    websiteKey: string;
    endpoint?: string;
    debug?: boolean;
    sdk?: string;
    sdkVersion?: string;
    integrationType?: string;
};

type PageviewData = {
    url: string;
    method: string;
    userAgent: string | null;
    ref: string | null;
    ip: string | null;
    acceptHeader?: string | null;
    status: number;
    duration: number;
};

const DEFAULT_ENDPOINT = "https://api.siteline.ai/v1/intake/pageview";
const LIMITS = {
    URL_MAX_LENGTH: 2048,
    METHOD_MAX_LENGTH: 10,
    USER_AGENT_MAX_LENGTH: 512,
    REF_MAX_LENGTH: 2048,
    IP_MAX_LENGTH: 45,
    ACCEPT_HEADER_MAX_LENGTH: 1024,
    INTEGRATION_TYPE_MAX_LENGTH: 50,
    SDK_MAX_LENGTH: 50,
    SDK_VERSION_MAX_LENGTH: 20,
    STATUS_MIN: 0,
    STATUS_MAX: 999,
    DURATION_MIN: 0,
    DURATION_MAX: 300000,
} as const;
const TIMEOUT_MS = 5000;

class Siteline {
    private readonly key: string;
    private readonly endpoint: string;
    private readonly debug: boolean;
    private readonly sdk: string;
    private readonly sdkVersion: string;
    private readonly integrationType: string;

    constructor(config: SitelineConfig) {
        if (!config.websiteKey) throw new Error("[Siteline] Missing websiteKey.");
        this.key = config.websiteKey;
        this.endpoint = config.endpoint || DEFAULT_ENDPOINT;
        this.debug = config.debug || false;
        this.sdk = config.sdk || "@siteline/core";
        this.sdkVersion = config.sdkVersion || "1.0.9";
        this.integrationType = config.integrationType || "netlify-edge";
    }

    async track(data: PageviewData): Promise<void> {
        const payload = {
            websiteKey: this.key,
            url: String(data.url).slice(0, LIMITS.URL_MAX_LENGTH),
            method: String(data.method).toUpperCase().slice(0, LIMITS.METHOD_MAX_LENGTH),
            status: Math.max(LIMITS.STATUS_MIN, Math.min(LIMITS.STATUS_MAX, Number(data.status) || 0)),
            duration: Math.max(LIMITS.DURATION_MIN, Math.min(LIMITS.DURATION_MAX, Number(data.duration) || 0)),
            userAgent: data.userAgent ? String(data.userAgent).slice(0, LIMITS.USER_AGENT_MAX_LENGTH) : null,
            ref: data.ref ? String(data.ref).slice(0, LIMITS.REF_MAX_LENGTH) : null,
            ip: data.ip ? String(data.ip).slice(0, LIMITS.IP_MAX_LENGTH) : null,
            acceptHeader: data.acceptHeader ? String(data.acceptHeader).slice(0, LIMITS.ACCEPT_HEADER_MAX_LENGTH) : null,
            integrationType: this.integrationType.slice(0, LIMITS.INTEGRATION_TYPE_MAX_LENGTH),
            sdk: this.sdk.slice(0, LIMITS.SDK_MAX_LENGTH),
            sdkVersion: this.sdkVersion.slice(0, LIMITS.SDK_VERSION_MAX_LENGTH),
        };

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

        try {
            const res = await fetch(this.endpoint, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "User-Agent": `${this.sdk}/${this.sdkVersion}`,
                },
                body: JSON.stringify(payload),
                signal: controller.signal,
            });

            if (this.debug && !res.ok) console.error("[Siteline] HTTP error:", res.status);
            if (this.debug && res.ok) console.log("[Siteline] Tracked:", payload.url);
        } catch (err) {
            if (this.debug) console.error("[Siteline] Network error:", (err as Error).message);
        } finally {
            clearTimeout(timeout);
        }
    }
}

let siteline: Siteline | null = null;
let hasInitialized = false;

const extractIP = (headers: Headers): string | null =>
    headers.get('x-forwarded-for')?.split(',')[0].trim() ||
    headers.get('x-real-ip') ||
    headers.get('cf-connecting-ip') ||
    null;

const initSiteline = (): void => {
    if (hasInitialized) {
        return;
    }

    hasInitialized = true;

    const websiteKey = SITELINE_WEBSITE_KEY;
    const endpoint = SITELINE_ENDPOINT;

    if (!websiteKey) {
        console.warn('[Siteline] Missing SITELINE_WEBSITE_KEY constant. Tracking disabled.');
        return;
    }

    siteline = new Siteline({
        websiteKey,
        endpoint,
        debug: SITELINE_DEBUG,
        sdk: DEFAULT_SDK_NAME,
        sdkVersion: DEFAULT_SDK_VERSION,
        integrationType: DEFAULT_INTEGRATION_TYPE,
    });
};

const trackRequest = (request: Request, status: number, startTime: number): void => {
    void siteline?.track({
        url: request.url,
        method: request.method,
        status,
        duration: Math.round(performance.now() - startTime),
        userAgent: request.headers.get('user-agent'),
        ref: request.headers.get('referer'),
        ip: extractIP(request.headers),
        acceptHeader: request.headers.get('accept'),
    });
};

export default async (request: Request, context: NetlifyContext): Promise<Response> => {
    initSiteline();

    const startTime = performance.now();

    try {
        const response = await context.next();
        trackRequest(request, response.status, startTime);
        return response;
    } catch (error) {
        trackRequest(request, 500, startTime);

        if (SITELINE_DEBUG) {
            console.error('[Siteline] Edge function failed before response:', error);
        }

        throw error;
    }
};
