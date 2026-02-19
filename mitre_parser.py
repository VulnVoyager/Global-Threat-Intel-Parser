import requests
import json
import sys

VERSION = "18.1" 

def get_download_url(version):
    """
    Формирует прямую ссылку на JSON файл релиза MITRE ATT&CK.
    Пример: https://github.com/mitre/cti/releases/download/ATT%26CK-v18.1/enterprise-attack.json
    """
    # Кодируем символ '&' для URL, так как в ссылке он представлен как %26
    base_url = "https://github.com/mitre/cti/releases/download"
    release_tag = f"ATT%26CK-v{version}"
    filename = "enterprise-attack.json"
    
    return f"{base_url}/{release_tag}/{filename}"

def get_threat_groups(keyword, version=VERSION):
    url = get_download_url(version)
    
    print(f"[*] Загрузка данных из MITRE ATT&CK v{version}...")
    print(f"[*] URL: {url}")
    
    try:
        response = requests.get(url, timeout=60)
        
        if response.status_code == 404:
            print(f"\n[!] ОШИБКА 404: Файл для версии v{version} не найден.")
            print("    Проверьте правильность номера версии или наличие релиза:")
            print("    https://github.com/mitre/cti/releases")
            return []
            
        response.raise_for_status()
        # Парсим JSON
        data = response.json()
        print("[+] Данные успешно загружены.")
        
    except requests.exceptions.RequestException as e:
        print(f"\n[!] Ошибка сети при загрузке: {e}")
        return []
    except json.JSONDecodeError:
        print("\n[!] Ошибка: Полученные данные не являются корректным JSON.")
        return []

    objects = data.get('objects', [])
    matched_groups = []
    search_term = keyword.lower()
    
    # Расширенный список синонимов для точности поиска
    synonyms_map = {
        'healthcare': ['hospital', 'pharmaceutical', 'clinic', 'medical', 'health care'],
        'finance': ['banking', 'financial', 'insurance'],
        'energy': ['energy', 'oil', 'gas', 'utility'],
        'government': ['government', 'state', 'public sector'],
        'telecom': ['telecom', 'communication', 'isp'],
        'manufacturing': ['manufacturing', 'industrial']
    }

    search_terms = [search_term]
    if search_term in synonyms_map:
        search_terms.extend(synonyms_map[search_term])
        print(f"[*] В поиск включены синонимы: {', '.join(synonyms_map[search_term])}")

    print(f"[*] Сканирование {len(objects)} объектов на предмет группировок (intrusion-set)...")

    count_scanned = 0
    for obj in objects:
        # Фильтр только по группировкам
        if obj.get('type') != 'intrusion-set':
            continue
        
        # Пропускаем отозванные (deprecated), если нужно только актуальное
        # Если нужно видеть историю, закомментируйте следующую строку
        if obj.get('x_mitre_deprecated', False):
            continue
            
        count_scanned += 1
        name = obj.get('name', 'Unknown')
        description = obj.get('description', '').lower()
        
        is_match = False
        
        # 1. Поиск в названии
        if any(term in name.lower() for term in search_terms):
            is_match = True
        
        # 2. Поиск в описании
        if not is_match and any(term in description for term in search_terms):
            is_match = True

        if is_match:
            # Извлекаем внешний ID и ссылку
            ext_refs = obj.get('external_references', [])
            mitre_id = "N/A"
            url_link = "#"
            
            for ref in ext_refs:
                if ref.get('source_name') == 'mitre-attack':
                    mitre_id = ref.get('external_id', 'N/A')
                    url_link = f"https://attack.mitre.org/groups/{mitre_id}/"
                    break

            group_info = {
                "name": name,
                "aliases": obj.get('aliases', []),
                "description_full": obj.get('description', ''),
                "description_preview": description[:250].replace('\n', ' ') + "...",
                "mitre_id": mitre_id,
                "url": url_link,
                "matrix_version": f"v{version}"
            }
            matched_groups.append(group_info)

    print(f"[*] Проанализировано группировок: {count_scanned}")
    return matched_groups

if __name__ == "__main__":
    print("--- MITRE ATT&CK Group Parser (v18.1 Ready) ---")
    
    user_keyword = input("\nВведите ключевое слово: ").strip()
    
    if not user_keyword:
        print("Ключевое слово не введено. Выход.")
        sys.exit(1)

    results = get_threat_groups(user_keyword)

    if results:
        print(f"\n{'='*20} РЕЗУЛЬТАТЫ ({len(results)}) {'='*20}")
        for i, group in enumerate(results, 1):
            print(f"\n[{i}] {group['name']} | ID: {group['mitre_id']}")
            print(f"    Алиасы: {', '.join(group['aliases']) if group['aliases'] else 'Нет'}")
            print(f"    Описание: {group['description_preview']}")
            print(f"    Ссылка: {group['url']}")
        
        print("\n" + "="*60)
        save_option = input("Сохранить полный отчет в JSON файл? (y/n): ").lower()
        
        if save_option == 'y':
            # Имя файла включает версию и запрос, чтобы не путаться
            safe_keyword = "".join(c for c in user_keyword if c.isalnum() or c in (' ', '_')).rstrip().replace(' ', '_')
            filename = f"mitre_groups_v{VERSION.replace('.', '_')}_{safe_keyword}.json"
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=4)
            
            print(f"[+] Данные успешно сохранены в файл: {filename}")
            print(f"    Количество записей: {len(results)}")
    else:
        print("\n[-] Группировки по вашему запросу не найдены в этой версии матрицы.")
        print("    Попробуйте проверить написание слова или использовать синоним (на английском).")