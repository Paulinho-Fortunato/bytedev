def test_xss_in_comments():
    print("[🔍] Testando XSS em comentários...")
    article_slug = "introducao-ao-hacking-etico"
    article_url = f"{BASE_URL}/article/{article_slug}"
    
    comment_data = {
        "author": "SecurityBot",
        "email": "bot@security.test",
        "content": XSS_PAYLOAD
    }
    response = requests.post(f"{BASE_URL}/article/{article_slug}/comment", data=comment_data)
    
    if response.status_code in (200, 302):
        page = requests.get(article_url)
        if "<script>" in page.text or "alert(" in page.text:
            print("❌ VULNERÁVEL: Script foi executado!")
        else:
            print("✅ SEGURO: Comentário exibido como texto puro.")
    else:
        print(f"⚠️  Falha ao postar comentário (status: {response.status_code}).")