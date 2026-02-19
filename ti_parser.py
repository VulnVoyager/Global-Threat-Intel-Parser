import requests
import json
import sys
import pandas as pd
from io import StringIO
import time
import re

VERSION = "18.1"
SHEET_ID = "1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU"

REGION_GIDS = [
    "361554658",
    "1636225066",
    "1905351590",
    "376438690",
    "300065512",
    "2069598202",
    "574287636",
    "438782970"
]

MITRE_BASE_URL = "https://github.com/mitre/cti/releases/download"

def normalize_name(name):
    """Приводит имя группы к каноническому виду для сравнения"""
    if not name:
        return ""
    s = re.sub(r'[^a-z0-9]', '', name.lower())
    return s

def get_mitre_groups(keyword, version):
    """Парсинг MITRE ATT&CK"""
    release_tag = f"ATT%26CK-v{version}"
    url = f"{MITRE_BASE_URL}/{release_tag}/enterprise-attack.json"
    
    print(f"[*] Загрузка MITRE ATT&CK v{version}...")
    try:
        resp = requests.get(url, timeout=60)
        if resp.status_code == 404:
            print(f"[!] MITRE v{version} не найден.")
            return []
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[!] Ошибка MITRE: {e}")
        return []

    objects = data.get('objects', [])
    results = []
    search_term = keyword.lower()
    
    synonyms_map = {
        'healthcare': ['медицина', 'здравоохранение', 'hospital', 'pharmaceutical', 'medical'],
        'finance': ['банк', 'финансы', 'banking', 'financial'],
        'energy': ['энергетика', 'energy', 'oil', 'gas'],
        'government': ['правительство', 'government', 'state'],
        'telecom': ['телеком', 'telecom', 'communication'],
        'manufacturing': ['производство', 'manufacturing', 'industrial']
    }
    terms = [search_term] + synonyms_map.get(search_term, [])

    for obj in objects:
        if obj.get('type') != 'intrusion-set' or obj.get('x_mitre_deprecated', False):
            continue
        
        name = obj.get('name', '')
        desc = obj.get('description', '').lower()
        aliases = obj.get('aliases', [])
        
        text_blob = f"{name} {desc} {' '.join(aliases)}".lower()
        if any(t in text_blob for t in terms):
            ext_refs = obj.get('external_references', [])
            mid = "N/A"
            link = "#"
            for ref in ext_refs:
                if ref.get('source_name') == 'mitre-attack':
                    mid = ref.get('external_id', 'N/A')
                    link = f"https://attack.mitre.org/groups/{mid}/"
                    break
            
            results.append({
                "source": "MITRE ATT&CK",
                "name": name,
                "norm_name": normalize_name(name),
                "aliases": aliases,
                "details": desc[:300].replace('\n', ' '),
                "id": mid,
                "url": link,
                "region": "Global"
            })
    print(f"[+] Найдено в MITRE: {len(results)}")
    return results

def parse_sheet_tab(sheet_id, gid, keyword):
    """Скачивает и парсит конкретный лист таблицы"""
    csv_url = f"https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv&id={sheet_id}&gid={gid}"
    
    try:
        resp = requests.get(csv_url, timeout=30)
        if resp.status_code != 200:
            return []
        
        # Читаем CSV
        df = pd.read_csv(StringIO(resp.text), dtype=str).fillna('')
        
        results = []
        search_term = keyword.lower()
        
        for index, row in df.iterrows():
            row_text = " ".join(row.values).lower()
            
            if search_term in row_text:
                potential_name = ""
                for val in row.values:
                    if val and len(str(val).strip()) > 2:
                        potential_name = str(val).strip()
                        break
                
                if not potential_name:
                    continue

                context = " | ".join([str(v) for v in row.values if v])[:300]
                
                results.append({
                    "source": "Google Sheet",
                    "name": potential_name,
                    "norm_name": normalize_name(potential_name),
                    "aliases": [],
                    "details": context.replace('\n', ' '),
                    "id": "N/A (Sheet)",
                    "url": f"https://docs.google.com/spreadsheets/d/{sheet_id}/edit#gid={gid}",
                    "region": f"Sheet-GID-{gid}"
                })
        return results
    except Exception as e:
        return []

def deduplicate_results(mitre_list, sheet_list):
    """
    Объединяет списки, отдавая приоритет MITRE.
    Если группа есть в обоих списках (по нормализованному имени), оставляем версию из MITRE.
    """
    final_results = []
    seen_names = {}

    for item in mitre_list:
        key = item['norm_name']
        seen_names[key] = item
        item['confirmed_in'] = ["MITRE"]

    for item in sheet_list:
        key = item['norm_name']
        
        if key in seen_names:
            existing = seen_names[key]
            if "Google Sheet" not in existing.get('confirmed_in', []):
                existing['confirmed_in'].append("Google Sheet")
                existing['source'] = "MITRE ATT&CK + Google Sheet"
                existing['details'] += f"\n[Также найдено в Google Sheet: {item['url']}]"
        else:
            seen_names[key] = item
            item['confirmed_in'] = ["Google Sheet"]

    return list(seen_names.values())

if __name__ == "__main__":
    print("--- Global Threat Intel Parser (v18.1 + All Regions) ---")
    user_keyword = input("\nВведите ключевое слово (например, healthcare): ").strip()
    
    if not user_keyword:
        sys.exit(1)

    mitre_results = get_mitre_groups(user_keyword, VERSION)
    
    sheet_results = []
    print(f"[*] Сканирование {len(REGION_GIDS)} регионов в Google Таблице...")
    
    for i, gid in enumerate(REGION_GIDS, 1):
        time.sleep(0.3) 
        print(f"    [{i}/{len(REGION_GIDS)}] Регион GID:{gid}...", end="\r")
        res = parse_sheet_tab(SHEET_ID, gid, user_keyword)
        sheet_results.extend(res)
    
    print(f"\n[+] Найдено в Google Sheets (до очистки): {len(sheet_results)}")

    final_results = deduplicate_results(mitre_results, sheet_results)
    
    final_results.sort(key=lambda x: (len(x.get('confirmed_in', [])), x['source']), reverse=True)

    if final_results:
        print(f"\n{'='*20} ИТОГО УНИКАЛЬНЫХ ГРУПП: {len(final_results)} {'='*20}")
        
        for i, group in enumerate(final_results, 1):
            badge = "✅" if len(group.get('confirmed_in', [])) > 1 else "ℹ️"
            sources = ", ".join(group.get('confirmed_in', []))
            
            print(f"\n[{i}] {badge} {group['name']}")
            print(f"    Источники: {sources}")
            if group['id'] != "N/A (Sheet)":
                print(f"    MITRE ID: {group['id']}")
            if group['aliases']:
                print(f"    Алиасы: {', '.join(group['aliases'][:5])}")
            print(f"    Детали: {group['details'][:150]}...")
            print(f"    Ссылка: {group['url']}")
        
        save = input("\nСохранить чистый отчет в JSON? (y/n): ").lower()
        if save == 'y':
            fname = f"threat_intel_{user_keyword}_deduped.json"
            clean_results = []
            for g in final_results:
                cg = g.copy()
                del cg['norm_name']
                del cg['confirmed_in']
                clean_results.append(cg)
                
            with open(fname, 'w', encoding='utf-8') as f:
                json.dump(clean_results, f, ensure_ascii=False, indent=4)
            print(f"[+] Сохранено в {fname}")
    else:
        print("\n[-] Ничего не найдено.")
