"""Streamlit presentation for the existing semantic search and RAG pipeline."""
import json
import os
import sys
from html import escape
from pathlib import Path
from time import monotonic

import altair as alt
import streamlit as st

ROOT = Path(__file__).resolve().parent
INDEX_DIR = ROOT / "data/index"
os.environ.setdefault("HF_HOME", str(ROOT / "data/model_cache"))

from mitre_final.rag import DEFAULT_LLM, NOTICE, RagError, run_rag
from mitre_final.search import DEFAULT_MODEL, search

SEMANTIC = "Anlamsal arama"
RAG = "Kaynaklı açıklama (RAG)"
EXAMPLES = {
    "PowerShell": "Güvenlik ekibi, bir Windows uç noktasında PowerShell üzerinden şüpheli bir betik çalıştırıldığını gözlemledi.",
    "Zamanlanmış görev": "An endpoint alert reported a new Windows scheduled task associated with a suspicious executable at user logon.",
    "Kimlik bilgilerine erişim": "Endpoint telemetry recorded an unexpected process accessing LSASS memory.",
    "Yetersiz bağlam": "Kullanıcı bilgisayarında hesap makinesini açtı.",
}

STYLES = """
<style>
.block-container {max-width: 78rem; padding-top: 2.5rem;}
.mitre-hero {
    background: linear-gradient(115deg, #0a172b, #153957);
    border: 1px solid #315773;
    border-radius: 1.25rem;
    padding: clamp(1.3rem, 4vw, 3rem);
    margin-bottom: 1.5rem;
    color: #f3f8ff;
}
.mitre-hero h1 {color: inherit; padding: 0; font-size: clamp(2rem, 5vw, 3.5rem);}
.mitre-hero p {color: #d7e7f4; margin: 0.5rem 0 0; font-size: 1.05rem;}
.mitre-hero .mitre-label {color: #8ce4db; font-size: .8rem; font-weight: 700; letter-spacing: .1em;}
.mitre-badges {display: flex; flex-wrap: wrap; gap: .45rem; margin: .25rem 0 .75rem;}
.mitre-badge {background: #d7f5f1; color: #103f43; border-radius: 1rem; padding: .2rem .65rem; font-size: .82rem;}
</style>
"""

HERO = """
<header class="mitre-hero">
  <div class="mitre-label">MITRE ATT&amp;CK® ENTERPRISE</div>
  <h1>MITRE-RAG</h1>
  <p>Güvenlik olaylarını ATT&amp;CK teknikleriyle eşleştirin ve kaynakları inceleyin.</p>
</header>
"""


def load_example():
    st.session_state["incident"] = EXAMPLES[st.session_state["example"]]


def similarity(hit):
    return hit["score"] if "score" in hit else hit["retrieval_score"]


def render_chart(hits):
    rows = [{"technique": hit["attack_id"], "name": hit["name"], "score": similarity(hit)}
            for hit in hits]
    chart = (
        alt.Chart(alt.Data(values=rows))
        .mark_bar(color="#2d8d88")
        .encode(
            x=alt.X("score:Q", title="Kosinüs benzerliği",
                    scale=alt.Scale(domain=[-1, 1]), axis=alt.Axis(format=".1f")),
            y=alt.Y("technique:N", title=None, sort=[row["technique"] for row in rows]),
            tooltip=[alt.Tooltip("technique:N", title="ATT&CK"),
                     alt.Tooltip("name:N", title="Teknik"),
                     alt.Tooltip("score:Q", title="Benzerlik", format=".4f")],
        )
        .properties(height=max(100, 32 * len(rows)))
    )
    st.altair_chart(chart, use_container_width=True)
    st.caption("Kosinüs benzerliği −1 ile +1 arasındadır. Adaylar en yüksek skordan başlayarak sıralanır.")


def render_hit(hit, match):
    with st.container(border=True):
        heading, score = st.columns([4, 1])
        with heading:
            st.subheader(f"{hit['attack_id']} · {hit['name']}")
        with score:
            st.metric("Benzerlik", f"{similarity(hit):.4f}")
        if hit.get("tactics"):
            badges = "".join(
                f'<span class="mitre-badge">{escape(tactic.replace("-", " ").title())}</span>'
                for tactic in hit["tactics"]
            )
            st.markdown(f'<div class="mitre-badges">{badges}</div>', unsafe_allow_html=True)
        if hit.get("parent_attack_id"):
            st.caption(f"Üst teknik · {hit['parent_attack_id']}")
        if match:
            st.markdown("**Neden bu teknik?**")
            st.write(match["explanation"])
            st.caption("ATT&CK kaynak alıntısı")
            st.text(match["evidence_quote"])
        with st.expander("Aramada bulunan kaynak metni"):
            st.text(hit.get("evidence_excerpt", hit.get("excerpt", "")))
        st.link_button("ATT&CK teknik sayfasını aç", hit["source_url"])


def render_results(saved):
    result = saved["result"]
    is_rag = "matches" in result
    hits = result["retrieved_sources"] if is_rag else result["results"]
    matches = {match["attack_id"]: match for match in result.get("matches", [])}

    st.header("Analiz sonucu")
    count, best, elapsed = st.columns(3)
    count.metric("Bulunan aday", len(hits))
    best.metric("En yüksek benzerlik", f"{max(map(similarity, hits)):.4f}" if hits else "—")
    elapsed.metric("Analiz süresi", f"{saved['elapsed']:.1f} sn")

    with st.expander("Analiz edilen olay ve yöntem"):
        st.caption(saved["mode"])
        st.text(result["query"])
    if is_rag:
        st.subheader("Kaynaklı değerlendirme")
        st.write(result["summary"])
        if not matches:
            st.warning("Kaynaklarla desteklenen bir eşleşme üretilemedi. İnceleme için ek bağlam gerekiyor.")
        if result["additional_data_needed"]:
            st.markdown("**İnceleme için gereken ek bilgiler**")
            for item in result["additional_data_needed"]:
                st.write(f"• {item}")

    st.subheader("Aday teknikler")
    if hits:
        if not is_rag:
            st.caption("Olayla ilgili kaynaklı açıklama için RAG modunda yeniden analiz edebilirsiniz.")
        render_chart(hits)
        for hit in hits:
            render_hit(hit, matches.get(hit["attack_id"]))
    else:
        st.info("İndekste aday teknik bulunamadı.")

    st.download_button("Sonucu JSON olarak indir", json.dumps(result, ensure_ascii=False, indent=2),
                       file_name="mitre_rag_analiz.json", mime="application/json")
    with st.expander("Ayrıntılı JSON çıktısı"):
        st.json(result)


def main():
    if sys.platform == "darwin":
        import pyarrow as pa

        # Arrow's mimalloc backend can crash when Streamlit serializes result tables.
        pa.set_memory_pool(pa.system_memory_pool())

    st.set_page_config(page_title="MITRE-RAG | Olay Analizi", page_icon="🛡️", layout="wide")
    st.markdown(STYLES + HERO, unsafe_allow_html=True)

    with st.sidebar:
        st.header("Analiz ayarları")
        mode = st.radio("Çalışma biçimi", [SEMANTIC, RAG],
                        help="RAG, bulunan ATT&CK kaynaklarını kullanarak yerel modelle açıklama üretir.")
        top_k = st.slider("Aday teknik sayısı", 1, 10, 3)
        st.divider()
        st.subheader("Sistem bilgisi")
        st.markdown("**Veri kaynağı**  \nMITRE ATT&CK Enterprise · STIX")
        st.markdown("**Arama**  \nAnlamsal arama · Kosinüs benzerliği")
        st.markdown(f"**Embedding modeli**  \n`{DEFAULT_MODEL.split('/')[-1]}`")
        st.markdown(f"**Yerel dil modeli**  \n`{DEFAULT_LLM}` · Ollama")

        with st.expander("Analiz nasıl çalışır?"):
            st.write("Sistem, olay metnine en yakın ATT&CK kaynaklarını sıralar. "
                     "RAG modunda yerel model bu kaynaklara dayanarak açıklama üretir. "
                     "Uygulama kaynak kimliklerini ve alıntıları kontrol eder.")

    with st.container(border=True):
        st.header("Güvenlik olayı")
        st.caption("Gözlenen davranışı, ilgili süreci ve varsa alarm veya günlük ayrıntılarını yazın.")
        example, action = st.columns([3, 2], vertical_alignment="bottom")
        with example:
            st.selectbox("Örnek olay", list(EXAMPLES), key="example")
        with action:
            st.button("Örneği girdiye aktar", on_click=load_example, use_container_width=True)
        with st.form("analysis", border=False):
            query = st.text_area("Olay açıklaması", key="incident", height=160,
                                 placeholder="Örn. Uç nokta alarmında bilinmeyen bir süreç gözlendi…")
            submitted = st.form_submit_button("Analiz et", type="primary", use_container_width=True)
    st.caption(NOTICE)

    if submitted:
        st.session_state.pop("analysis_result", None)
        if not query.strip():
            st.warning("Önce bir olay açıklaması girin.")
            return
        started = monotonic()
        message = ("ATT&CK kaynakları taranıyor…" if mode == SEMANTIC
                   else "ATT&CK kaynakları taranıyor ve yerel model açıklama üretiyor…")
        try:
            with st.spinner(message):
                result = (search(INDEX_DIR, query, top_k, offline=True) if mode == SEMANTIC
                          else run_rag(query, INDEX_DIR, top_k, offline=True))
        except (RagError, ValueError, OSError) as exc:
            st.error(f"Analiz tamamlanamadı: {exc}")
            st.caption("İndeks ve embedding önbelleğini kontrol edin. RAG için Ollama ve qwen3:8b gerekir.")
            return
        st.session_state["analysis_result"] = {
            "mode": mode, "result": result, "elapsed": monotonic() - started,
        }

    saved = st.session_state.get("analysis_result")
    if saved:
        render_results(saved)
    else:
        with st.container(border=True):
            st.subheader("İlk analizinizi başlatın")
            st.write("Bir olay yazın veya örnek olay yükleyin. Aday teknikler ve kaynakları burada görünecek.")


if __name__ == "__main__":
    main()
