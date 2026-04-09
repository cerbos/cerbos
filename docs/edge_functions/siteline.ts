import { Siteline } from 'https://esm.sh/@siteline/core@1.0.9';

type NetlifyContext = {
    next: () => Promise<Response>;
};

const SITELINE_WEBSITE_KEY = process.env.SITELINE_WEBSITE_KEY;
const SITELINE_DEBUG = false;
const SITELINE_ENDPOINT = 'https://api.siteline.ai/v1/intake/pageview'

const DEFAULT_SDK_NAME = '@siteline/core';
const DEFAULT_SDK_VERSION = '1.0.9';
const DEFAULT_INTEGRATION_TYPE = 'netlify-edge';

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
