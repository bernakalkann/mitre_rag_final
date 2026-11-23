"""BM25 ranking and reciprocal rank fusion for ATT&CK techniques."""
import re
import unicodedata
from collections import Counter, defaultdict
from math import log1p

K1 = 1.2
B = 0.75
RRF_CONSTANT = 60
FUSION_DEPTH = 50
TOKEN = re.compile(r"\bt\d{4}(?:\.\d{3})?\b|[^\W_]+")
SENTENCE_BREAK = re.compile(r"(?<=[.!?])\s+")
STOP_WORDS = frozenset(
    "a an the this that these those to for of in on at by and or as is are was were be "
    "been with from it its can may use used using bir ve ile için bu şu da de veya olarak".split()
)


def tokenize(text):
    normalized = unicodedata.normalize("NFKC", text).casefold().replace("\u0307", "")
    return [word for word in TOKEN.findall(normalized) if word not in STOP_WORDS]


class BM25Index:
    def __init__(self, records):
        self.records = records
        self.postings = defaultdict(list)
        self.lengths = []
        for index, record in enumerate(records):
            terms = tokenize(f"{record['attack_id']} {record['name']} {record['description']}")
            self.lengths.append(len(terms))
            for term, frequency in Counter(terms).items():
                self.postings[term].append((index, frequency))
        self.average_length = sum(self.lengths) / len(records) if records else 0

    def rank(self, query, top_k):
        terms = sorted(set(tokenize(query)))
        term_set = set(terms)
        scores = defaultdict(float)
        for term in terms:
            postings = self.postings.get(term, ())
            idf = log1p((len(self.records) - len(postings) + 0.5) / (len(postings) + 0.5))
            for index, frequency in postings:
                length_factor = 1 - B + B * self.lengths[index] / self.average_length
                scores[index] += idf * frequency * (K1 + 1) / (frequency + K1 * length_factor)

        ordered = sorted(scores, key=lambda index: (-scores[index], self.records[index]["attack_id"]))
        hits = []
        for rank, index in enumerate(ordered[:top_k], start=1):
            record = self.records[index]
            sentences = SENTENCE_BREAK.split(record["description"])
            excerpt = max(sentences, key=lambda sentence: len(term_set.intersection(tokenize(sentence))))
            hits.append({
                "rank": rank,
                "attack_id": record["attack_id"],
                "name": record["name"],
                "score": scores[index],
                "source_url": record["source_url"],
                "parent_attack_id": record["parent_attack_id"],
                "tactics": record.get("tactics", []),
                "evidence_excerpt": excerpt,
            })
        return hits


def reciprocal_rank_fusion(rankings, top_k):
    candidates = {}
    contributions = defaultdict(dict)
    for method, hits in rankings.items():
        for rank, hit in enumerate(hits, start=1):
            attack_id = hit["attack_id"]
            if method in contributions[attack_id]:
                continue
            candidates.setdefault(attack_id, hit)
            contributions[attack_id][method] = rank

    scores = {attack_id: sum(1 / (RRF_CONSTANT + rank) for rank in ranks.values())
              for attack_id, ranks in contributions.items()}
    ordered = sorted(scores, key=lambda attack_id: (-scores[attack_id], attack_id))
    return [{**candidates[attack_id], "rank": rank, "score": scores[attack_id],
             "component_ranks": contributions[attack_id]}
            for rank, attack_id in enumerate(ordered[:top_k], start=1)]
