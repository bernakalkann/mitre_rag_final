"""Early presentation interface for the existing week 8 pipeline.

Run from the repository root: streamlit run streamlit_app.py
"""
import json
import os
from pathlib import Path
from time import monotonic

import streamlit as st

ROOT = Path(__file__).resolve().parent
os.environ.setdefault("HF_HOME", str(ROOT / "data/model_cache"))

from mitre_final.rag import NOTICE, RagError, run_rag
from mitre_final.search import search

EXAMPLES = {
    "PowerShell": "Saldırgan Windows bilgisayarda PowerShell kullanarak kötü amaçlı bir betik çalıştırdı.",
    "Zamanlanmış görev": "An attacker created a Windows scheduled task that runs a malicious executable every time the user logs in.",
    "Kimlik bilgilerine erişim": "An attacker accessed LSASS process memory to extract user credentials.",
    "Yetersiz bağlam": "Kullanıcı bilgisayarında hesap makinesini açtı.",
}


def main():
    st.set_page_config(page_title="MITRE-RAG | Olay Analizi", page_icon="🛡️", layout="wide")
    st.title("MITRE-RAG")
    st.write("Güvenlik olaylarından ATT&CK teknik adaylarına")
    st.caption("İlk 8 haftanın çalışan akışı · Erken demo arayüzü")
    with st.sidebar:
        st.header("Analiz ayarları")
        mode = st.radio("Çalışma biçimi", ["Anlamsal arama", "Kaynaklı açıklama (RAG)"])
        top_k = st.slider("Aday teknik sayısı", 1, 10, 3)
        st.divider()
        st.write("**Embedding:** Çok dilli MiniLM")
        st.write("**Yerel LLM:** Qwen3:8B / Ollama")
        st.caption("BM25 ve hibrit arama sonraki aşamalarda eklenecek.")
    st.info(NOTICE)
    with st.expander("Sistemde ne oluyor?"):
        st.write("Olay açıklaması aynı embedding modeliyle vektöre çevrilir. "
                 "ATT&CK metin parçalarıyla kosinüs benzerliği hesaplanır ve farklı teknikler sıralanır. "
                 "RAG seçildiğinde bulunan kaynaklar yerel LLM'ye verilerek açıklama üretilir; "
                 "kaynak kimlikleri ve alıntılar uygulama tarafından kontrol edilir.")
    example = st.selectbox("Örnek olay", list(EXAMPLES))
    if st.button("Örneği girdiye aktar"):
        st.session_state["incident"] = EXAMPLES[example]
    with st.form("analysis"):
        query = st.text_area("Olay açıklaması", key="incident", height=140,
                             placeholder="Gözlenen davranışı birkaç cümleyle açıklayın…")
        submitted = st.form_submit_button("Analiz et", type="primary")
    if submitted:
        st.session_state.pop("analysis_result", None)
        if not query.strip():
            st.warning("Önce bir olay açıklaması girin.")
        else:
            started = monotonic()
            try:
                with st.spinner("ATT&CK kaynakları taranıyor…" if mode == "Anlamsal arama" else
                                "Kaynaklar taranıyor ve yerel model açıklama üretiyor…"):
                    if mode == "Anlamsal arama":
                        result = search(ROOT / "data/index", query, top_k, offline=True)
                    else:
                        result = run_rag(query, ROOT / "data/index", top_k, offline=True)
                st.session_state["analysis_result"] = {
                    "mode": mode, "result": result, "elapsed": monotonic() - started}
            except (RagError, ValueError, OSError) as exc:
                st.error(f"Analiz tamamlanamadı: {exc}")
                st.caption("İndeks ve embedding önbelleği hazır olmalı. RAG için Ollama ve qwen3:8b çalışır durumda olmalı.")
    saved = st.session_state.get("analysis_result")
    if not saved:
        return
    result = saved["result"]
    st.divider()
    st.subheader("Analiz sonucu")
    st.caption(f"Çalıştırılan yöntem: {saved['mode']} · Toplam süre: {saved['elapsed']:.1f} saniye")
    st.write("**Analiz edilen olay:**", result["query"])
    if "matches" in result:
        st.write(result["summary"])
        if not result["matches"]:
            st.warning("Kaynaklarla desteklenen bir eşleşme üretilemedi; ek bağlam gerekiyor.")
        for match in result["matches"]:
            st.markdown(f"### {match['attack_id']} · {match['name']}")
            st.write(match["explanation"])
            st.caption("ATT&CK kaynak alıntısı")
            st.text(match["evidence_quote"])
            st.link_button("ATT&CK kaynağını aç", match["source_url"])
        if result["additional_data_needed"]:
            st.write("**İnceleme için gereken ek bilgiler**")
            for item in result["additional_data_needed"]:
                st.write(f"• {item}")
        hits = result["retrieved_sources"]
    else:
        hits = result["results"]
    st.subheader("Aramada bulunan adaylar")
    st.caption("Bu liste arama sıralamasıdır. Skorlar saldırı olasılığını veya kesin eşleşmeyi göstermez.")
    st.dataframe([{"ATT&CK kodu": h["attack_id"], "Teknik": h["name"],
                   "Kosinüs benzerliği": round(h.get("score", h.get("retrieval_score", 0)), 4)}
                  for h in hits], hide_index=True, use_container_width=True)
    for hit in hits:
        with st.expander(f"{hit['attack_id']} · {hit['name']} — kaynak metni"):
            st.text(hit.get("evidence_excerpt", hit.get("excerpt", "")))
            st.link_button("Resmî teknik sayfası", hit["source_url"])
    st.download_button("Sonucu JSON olarak indir", json.dumps(result, ensure_ascii=False, indent=2),
                       file_name="mitre_rag_analiz.json", mime="application/json")
    with st.expander("Ayrıntılı çıktı"):
        st.json(result)


if __name__ == "__main__":
    main()
