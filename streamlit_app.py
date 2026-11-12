"""Streamlit presentation for the existing semantic search and RAG pipeline."""
import json
import sys
from collections import Counter
from html import escape
from pathlib import Path
from time import monotonic_ns

import streamlit as st
import streamlit.components.v1 as components

from mitre_final.rag import DEFAULT_LLM, NOTICE
from mitre_final.search import DEFAULT_MODEL
from mitre_final.service import EXAMPLES, RAG, ROOT, SEMANTIC, analyze, read_attack_manifest


def render_header():
    styles = (ROOT / "assets/workspace.css").read_text(encoding="utf-8")
    st.markdown(f"<style>{styles}</style>" + """
<header class="work-header">
  <strong class="work-brand">MITRE-RAG</strong>
  <span>Güvenlik olayı inceleme</span>
</header>
""", unsafe_allow_html=True)


def render_result_heading(title, detail):
    st.markdown(
        f'<div class="result-heading"><h2>{escape(title)}</h2>'
        f'<p>{escape(detail)}</p></div>', unsafe_allow_html=True,
    )


def focus_section(selector, narrow_only=False):
    # A fresh iframe runs only in response to an analysis or an explicit selection.
    components.html(f"<!-- {monotonic_ns()} -->" + f"""
<script>
const page = window.parent;
window.frameElement?.setAttribute("tabindex", "-1");
page.requestAnimationFrame(() => {{
    if ({str(narrow_only).lower()} && !page.matchMedia("(max-width: 740px)").matches) return;
    const heading = page.document.querySelector({json.dumps(selector)});
    if (!heading) return;
    heading.setAttribute("tabindex", "-1");
    heading.focus({{preventScroll: true}});
    const reduced = page.matchMedia("(prefers-reduced-motion: reduce)").matches;
    heading.scrollIntoView({{block: "start", behavior: reduced ? "instant" : "smooth"}});
}});
</script>
""", height=0, width=0)


def load_example():
    st.session_state["incident"] = EXAMPLES[st.session_state["example"]]


def similarity(hit):
    return hit["score"] if "score" in hit else hit["retrieval_score"]


def tactic_label(tactic):
    return tactic.replace("-", " ").title()


def render_chart(hits):
    rows = []
    for hit in hits:
        score = similarity(hit)
        position = 50 + 50 * min(0, max(-1, score))
        width = 50 * min(1, abs(score))
        rows.append(
            f'<div class="score-row"><code>{escape(hit["attack_id"])}</code>'
            f'<div class="score-track" aria-hidden="true">'
            f'<span style="left:{position:.3f}%;width:{width:.3f}%"></span></div>'
            f'<span>{score:.4f}</span></div>'
        )
    st.markdown('<div class="score-chart" role="group" aria-label="ATT&amp;CK benzerlik grafiği">'
                + "".join(rows) + "</div>", unsafe_allow_html=True)
    st.caption("Kosinüs benzerliği −1 ile +1 arasındadır. Çubuklar ortadaki sıfır çizgisinden başlar.")


def select_candidate(candidate):
    st.session_state["selected_candidate"] = candidate
    st.session_state["focus_evidence"] = True


def render_candidate_group(name, purpose, kind, candidates, selected, error):
    st.markdown(f'<div class="candidate-group"><div><h4>{escape(name)}</h4>'
                f'<small>{escape(purpose)}</small></div>'
                f'<span>{len(candidates)} aday</span></div>', unsafe_allow_html=True)
    if error:
        st.warning(error)
    elif not candidates:
        st.caption("Aday bulunamadı.")

    for rank, (identifier, title, score, _) in enumerate(candidates, start=1):
        candidate = (kind, identifier)
        st.button(f"`{rank:02d}`  {title} · `{identifier}` · `{score:.4f}`",
                  key=f"candidate_{kind}_{identifier}",
                  type="primary" if candidate == selected else "secondary",
                  use_container_width=True, on_click=select_candidate, args=(candidate,))


def render_evidence(selected, sources, matches, reference):
    if selected is None:
        st.caption("Kanıt gösterilebilecek bir aday bulunamadı.")
        return

    kind, identifier = selected
    _, title, score, hit = sources[selected]
    source_name = "MITRE ATT&CK" if kind == "attack" else "NIST CSF 2.0"
    st.markdown(f'<div class="evidence-meta" role="status">{source_name} · <code>{escape(identifier)}</code>'
                f' · Benzerlik {score:.4f}</div>', unsafe_allow_html=True)
    st.subheader(title)
    if kind == "attack":
        tactics = ", ".join(map(tactic_label, hit.get("tactics", [])))
        if tactics:
            st.caption(f"Taktik · {tactics}")
        if hit.get("parent_attack_id"):
            st.caption(f"Üst teknik · {hit['parent_attack_id']}")
        match = matches.get(identifier)
        if match:
            st.markdown("**Neden bu teknik?**")
            st.write(match["explanation"])
            st.markdown("#### Modelin kullandığı ATT&CK alıntısı")
            st.markdown(f'<blockquote class="evidence-quote">{escape(match["evidence_quote"])}</blockquote>',
                        unsafe_allow_html=True)
        description = hit.get("evidence_excerpt", hit.get("excerpt", ""))
        url = hit["source_url"]
        link_label = "Resmî ATT&CK kaydını aç"
    else:
        st.caption(f"İşlev · {hit['function']}")
        description = hit["description"]
        url = reference["source_url"]
        link_label = "NIST yayını · Ek A"

    st.markdown("#### Resmî kaynak metni")
    if description:
        st.markdown(f'<blockquote class="evidence-quote">{escape(description)}</blockquote>',
                    unsafe_allow_html=True)
    else:
        st.caption("Bu aday için yerel indekste kaynak metni bulunamadı.")
    st.link_button(link_label, url)


def render_attack_statistics(hits):
    with st.expander("Skor grafiği ve taktik dağılımı"):
        render_chart(hits)
        counts = Counter(tactic for hit in hits for tactic in set(hit.get("tactics", [])))
        if counts:
            rows = "".join(
                f"<tr><th scope='row'>{escape(tactic_label(tactic))}</th><td>{count}</td></tr>"
                for tactic, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
            )
            st.markdown("<table class='tactic-table'><thead><tr><th scope='col'>Taktik</th>"
                        "<th scope='col'>Aday sayısı</th></tr></thead><tbody>"
                        + rows + "</tbody></table>", unsafe_allow_html=True)
            st.caption("Bir teknik birden fazla taktikle ilişkili olabilir.")
        else:
            st.caption("Bu adaylar için taktik bilgisi bulunamadı.")


def render_results(saved):
    result = saved["result"]
    reference = saved["nist"]
    errors = saved.get("errors", {})
    hits = result.get("retrieved_sources", result.get("results", []))
    matches = {match["attack_id"]: match for match in result.get("matches", [])}
    attack = [(hit["attack_id"], hit["name"], similarity(hit), hit) for hit in hits]
    nist = [(hit["id"], hit["category"], hit["score"], hit)
            for hit in reference["results"]] if reference is not None else []
    sources = {("attack", row[0]): row for row in attack}
    sources.update({("nist", row[0]): row for row in nist})
    selected = st.session_state.get("selected_candidate")
    if selected not in sources:
        selected = next(iter(sources), None)

    with st.container(key="analysis_results"):
        state = "Kısmi analiz sonuçları" if errors else "Analiz sonuçları"
        render_result_heading(state, f"{saved['mode']} · {saved['elapsed']:.1f} sn")
        with st.expander("Analiz edilen olay"):
            st.text(result["query"])
        explanation = saved.get("explanation")
        if explanation and explanation["status"] == "error":
            st.warning(f"Model yorumu üretilemedi: {explanation['error']}")
        if "summary" in result:
            with st.expander("ATT&CK kaynaklarına dayalı model yorumu"):
                st.write(result["summary"])
                if not matches:
                    st.warning("Kaynaklarla desteklenen bir eşleşme üretilemedi. İnceleme için ek bağlam gerekiyor.")
                for item in result["additional_data_needed"]:
                    st.write(f"• {item}")

        with st.container(key="inspection_grid"):
            candidates, evidence = st.columns([5, 6])
            with candidates, st.container(border=True, key="candidate_list"):
                st.subheader("Adaylar")
                st.caption("Bir aday seçin. Benzerlik skorları her kaynak içinde sıralanır.")
                render_candidate_group("MITRE ATT&CK", "Olayla ilişkili teknikler",
                                       "attack", attack, selected, errors.get("attack"))
                render_candidate_group("NIST CSF 2.0", "İncelenecek savunma başlıkları",
                                       "nist", nist, selected, errors.get("nist"))
            with evidence, st.container(border=True, key="evidence_panel"):
                st.markdown('<h3 class="evidence-heading">Kaynak ve kanıt</h3>', unsafe_allow_html=True)
                render_evidence(selected, sources, matches, reference)

        st.caption(NOTICE)
        if hits:
            render_attack_statistics(hits)
        with st.expander("JSON çıktısı"):
            exported = {**result, "nist_csf": reference}
            st.download_button("JSON olarak indir", json.dumps(exported, ensure_ascii=False, indent=2),
                               file_name="mitre_rag_analiz.json", mime="application/json")
            st.json(exported)


def main():
    if sys.platform == "darwin":
        import pyarrow as pa

        # Arrow's mimalloc backend can crash when Streamlit serializes result tables.
        pa.set_memory_pool(pa.system_memory_pool())

    st.set_page_config(page_title="MITRE-RAG | Olay Analizi", page_icon="🛡️",
                       layout="wide", initial_sidebar_state="collapsed")
    manifest = read_attack_manifest()
    render_header()

    with st.sidebar:
        st.subheader("Sistem bilgisi")
        st.caption(f"ATT&CK teknik sayısı · {manifest.get('record_count', '—')}")
        st.caption(f"Embedding · {DEFAULT_MODEL.split('/')[-1]}")
        st.caption(f"Yerel model · {DEFAULT_LLM} / Ollama")

    with st.container(border=True, key="analysis_input"):
        st.title("Güvenlik olayı analizi")
        with st.form("analysis", border=False):
            query = st.text_area("Olay açıklaması", key="incident", height=112,
                                 placeholder="Ne gözlendi? İlgili süreci, cihazı veya alarmı yazın.")
            controls, submit = st.columns([5, 2], vertical_alignment="top")
            with controls, st.expander("Analiz ayarları"):
                mode = st.radio("Çalışma biçimi", [SEMANTIC, RAG],
                                help="RAG, ATT&CK kaynaklarından yerel modelle açıklama üretir.")
                top_k = st.slider("ATT&CK aday sayısı", 1, 10, 3)
            with submit:
                submitted = st.form_submit_button("Analiz et", type="primary", use_container_width=True)
        feedback = st.empty()
        with st.expander("Örnek olaylar"):
            example, action = st.columns([3, 1], vertical_alignment="bottom")
            with example:
                st.selectbox("Örnek olay", list(EXAMPLES), key="example")
            with action:
                st.button("Örneği girdiye aktar", on_click=load_example)

    if submitted:
        st.session_state.pop("analysis_result", None)
        st.session_state.pop("selected_candidate", None)
        if not query.strip():
            feedback.warning("Önce bir olay açıklaması girin.")
            return

        message = ("ATT&CK ve NIST kaynakları taranıyor…" if mode == SEMANTIC
                   else "Kaynaklar taranıyor ve yerel model ATT&CK açıklaması üretiyor…")
        with feedback.container(), st.spinner(message):
            response = analyze(query, "rag" if mode == RAG else "semantic", top_k)

        errors = {kind: response[kind]["error"] for kind in ("attack", "nist")
                  if response[kind]["status"] == "error"}
        export = response["export"]
        if export is None:
            feedback.error(" ".join(errors.values()))
            return

        st.session_state["analysis_result"] = {
            "mode": mode, "result": {key: value for key, value in export.items() if key != "nist_csf"},
            "nist": export["nist_csf"], "errors": errors, "elapsed": response["duration_ms"] / 1000,
            "explanation": response["explanation"],
        }

    saved = st.session_state.get("analysis_result")
    if saved:
        render_results(saved)
        if submitted:
            focus_section(".result-heading h2")
        elif st.session_state.pop("focus_evidence", False):
            focus_section(".evidence-heading", narrow_only=True)


if __name__ == "__main__":
    main()
