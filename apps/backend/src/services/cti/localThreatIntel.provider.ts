import { IOCType, ThreatIntelIOC, CTIMatchResult } from "@ransomware-cti/shared-types";
import fs from "fs";
import path from "path";
import { ThreatIntelProvider } from "./threatIntel.provider";

function loadConfiguredIndicators(): ThreatIntelIOC[] {
  const file = process.env.THREAT_INTEL_IOC_FILE;
  if (!file) return [];
  const parsed = JSON.parse(fs.readFileSync(path.resolve(file), "utf-8"));
  const list = Array.isArray(parsed) ? parsed : parsed?.iocs;
  if (!Array.isArray(list)) throw new Error(`THREAT_INTEL_IOC_FILE ${file}: expected an array of indicators`);
  for (const ioc of list) {
    if (!ioc?.indicator || !ioc?.type || typeof ioc.isMalicious !== "boolean") {
      throw new Error(`THREAT_INTEL_IOC_FILE ${file}: every indicator needs indicator, type and isMalicious`);
    }
  }
  return list;
}

export class LocalThreatIntelProvider implements ThreatIntelProvider {
  public name = "SentinelIQ Local Threat Intel Provider";

  private iocs: ThreatIntelIOC[];

  /**
   * Indicators come only from a configured feed file (THREAT_INTEL_IOC_FILE, a JSON array of
   * ThreatIntelIOC records, or {"iocs": [...]}) or from the caller (tests). Without one the
   * provider holds no indicators, and every lookup honestly reports "no match".
   */
  constructor(iocs?: ThreatIntelIOC[]) {
    this.iocs = iocs ?? loadConfiguredIndicators();
  }

  /** How many indicators are loaded; 0 means no feed is configured. */
  public get indicatorCount(): number {
    return this.iocs.length;
  }

  public async lookup(indicator: string, type?: IOCType): Promise<CTIMatchResult> {
    if (!indicator || typeof indicator !== "string") {
      return { matched: false };
    }

    const clean = indicator.trim().toLowerCase();

    const match = this.iocs.find((ioc) => {
      const iocInd = ioc.indicator.toLowerCase();
      const typeMatches = !type || ioc.type === type;
      if (!typeMatches) return false;

      // Exact match or substring / domain containment
      if (clean === iocInd) return true;
      if (ioc.type === "DOMAIN" && (clean.includes(iocInd) || iocInd.includes(clean))) return true;
      if (ioc.type === "URL" && (clean.includes(iocInd) || iocInd.includes(clean))) return true;
      if (ioc.type === "IP" && clean.includes(iocInd)) return true;
      if (ioc.type === "HASH" && clean === iocInd) return true;

      return false;
    });

    if (!match) {
      return { matched: false };
    }

    return {
      matched: true,
      indicator: match.indicator,
      type: match.type,
      isMalicious: match.isMalicious,
      confidence: match.confidence,
      severity: match.severity,
      threatCategory: match.threatCategory,
      tags: match.tags,
      source: match.source,
      matchedAt: new Date().toISOString(),
    };
  }

  public async lookupIP(ip: string): Promise<CTIMatchResult> {
    return this.lookup(ip, "IP");
  }

  public async lookupDomain(domain: string): Promise<CTIMatchResult> {
    return this.lookup(domain, "DOMAIN");
  }

  public async lookupHash(hash: string): Promise<CTIMatchResult> {
    return this.lookup(hash, "HASH");
  }

  public async lookupUrl(url: string): Promise<CTIMatchResult> {
    return this.lookup(url, "URL");
  }

  public async getAllIOCs(): Promise<ThreatIntelIOC[]> {
    return [...this.iocs];
  }
}

// Singleton instance
export const localThreatIntelProvider = new LocalThreatIntelProvider();
