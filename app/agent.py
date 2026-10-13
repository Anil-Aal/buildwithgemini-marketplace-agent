# ruff: noqa
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import urllib.request
from bs4 import BeautifulSoup
from ddgs import DDGS
from google.adk.agents import Agent
from google.adk.apps import App
from google.adk.models import Gemini
from google.genai import types

MODEL = "gemini-3.8-flash"



def search_marketplace_listings(
    query: str,
    region: str = "",
    domain_or_marketplace: str = "",
    max_results: int = 5,
) -> str:
    """Search the web or specific marketplace websites for product/subscription listings, pricing, and links.

    Args:
        query: Product, service, or brand to search for (e.g. 'DAZN subscription', 'PlayStation 5').
        region: Optional country or region name/code (e.g. 'US', 'UK', 'Spain', 'Germany').
        domain_or_marketplace: Optional specific marketplace domain or name to filter by (e.g. 'etsy.com', 'z2u.com', 'sellpass.io', 'g2a.com', 'eneba.com', 'ebay.com').
        max_results: Maximum number of search results to retrieve (default: 5).

    Returns:
        JSON string containing the list of search results with titles, URLs, and snippet descriptions.
    """
    search_terms = [query]
    if domain_or_marketplace:
        if "." in domain_or_marketplace:
            search_terms.append(f"site:{domain_or_marketplace.lower().strip()}")
        else:
            search_terms.append(f"site:{domain_or_marketplace.lower().strip()}.com OR {domain_or_marketplace}")
    if region:
        search_terms.append(region)
    search_terms.append("price OR discount OR subscription OR account")

    search_query = " ".join(search_terms)

    try:
        ddgs = DDGS()
        results = list(ddgs.text(search_query, max_results=max_results))
        if not results and domain_or_marketplace:
            # Fallback to broader search without strict site: operator
            fallback_query = f"{query} {domain_or_marketplace} price {region}".strip()
            results = list(ddgs.text(fallback_query, max_results=max_results))
        return json.dumps(results, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Search failed: {str(e)}"})


def fetch_listing_details(url: str) -> str:
    """Fetch content and extract readable text from a marketplace or product listing webpage.

    Args:
        url: The web URL of the listing or product page.

    Returns:
        Extracted text snippet containing pricing, subscription tiers, and product details.
    """
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            html = response.read()
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup(["script", "style", "noscript", "header", "footer", "nav"]):
                tag.extract()
            text = " ".join(soup.stripped_strings)
            return text[:3000]
    except Exception as e:
        return f"Failed to retrieve page {url}: {str(e)}"


root_agent = Agent(
    name="marketplace_price_agent",
    model=Gemini(
        model=MODEL,
        retry_options=types.HttpRetryOptions(attempts=3),
    ),
    instruction="""You are an expert Marketplace Price & Threat Intelligence Assistant specialized in uncovering and analyzing unauthorized, grey-market, and high-risk account resellers.

Your core mission is to find and investigate third-party sellers, decentralized digital storefronts, and account-reselling platforms, especially:
- **Gaming & Digital Account Reseller Marketplaces**: Z2U, PlayerAuctions, G2G, Eldorado.gg
- **Decentralized Automated Digital Webstores**: Sellpass.io, Sellix.io, Shoppy.gg
- **General Marketplaces with Masked / Grey Listings**: Etsy, eBay, AliExpress
- **P2P Forums / Channels**: Telegram / Discord bot checkouts referenced on web

When investigating a product, subscription, or brand:
1. **Target High-Risk Account Resellers Directly**:
   - Actively run searches targeting Z2U (`site:z2u.com`), Sellpass (`site:sellpass.io` / `sellpass`), Sellix (`sellix`), Etsy (`site:etsy.com`), and related reseller platforms.
   - Look for terms like: 'account', 'login', 'shared account', 'cheap subscription', 'lifetime pass', 'profile'.
2. **Collect Actionable Links & Seller Data**:
   - Provide direct URLs to active listings, seller store fronts, or category hubs on Z2U, Sellpass, Etsy, etc.
   - Extract the advertised price point, subscription length, and seller claims (e.g. "private profile", "shared slot", "with warranty").
3. **Analyze Seller Mechanics & Exploit Vectors**:
   - Detail how the reseller delivers the service (e.g. stolen/credential-stuffed accounts, autopay zombie accounts, BIN/currency exploitation, or temporary shared profiles).
4. **Present a Detailed Intelligence Breakdown**:
   - **Target Brand/Service & Scope**
   - **High-Risk Reseller Listings Directory**: For EVERY listing found, ALWAYS provide the **FULL, COMPLETE RAW URL** (e.g. `https://www.z2u.com/dazn/accounts-5-26059`) alongside markdown links, along with exact price, currency, seller name, and delivery method.
   - **Price Disparity Analysis** (Official Retail Price vs Reseller Price, % discount).
   - **Technical & Security Risk Assessment** (Revocation timeframe, TOS violation, IP/device conflict risks).
""",
    tools=[search_marketplace_listings, fetch_listing_details],
)

app = App(
    root_agent=root_agent,
    name="app",
)

