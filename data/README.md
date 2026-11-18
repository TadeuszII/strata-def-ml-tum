# Dane

Dane nie są przechowywane w repozytorium — w repo tylko opis, skąd je wziąć. Część źródeł (np. PhishTank) ma własne warunki korzystania.

## Google Drive (poza repo)

```
Mój dysk/phishing-tum/   (nazwa folderu może zostać)
├── data/raw/          # dane źródłowe bez zmian
├── data/processed/    # train / validation / test
├── mlruns/            # historia MLflow
└── models/            # modele przed publikacją
```

**Start każdego notatnika w Colabie:** zamontowanie Google Drive → `git clone` repo → `pip install -e ".[train]"`. Notatnik i kalkulator cech pochodzą z tego samego commita.

## Pobrane zbiory

- **PhreshPhish** — pobrany na Google Drive, zapisana konkretna wersja (commit hash) do powtarzalności. **Wersja: `eca603e0ecd4f698f8d4d226c088659e72681239`**, 1057 plików, 36,6 GB, pobrano 2026-11-01 do `MyDrive/phishing-tum/data/raw/phreshphish`.

## Źródła

| Źródło | Typ | Uwagi |
|---|---|---|
| **PhreshPhish** (Hugging Face, 2024–2025) — **główny zbiór dla modelu treści** | URL + **HTML wyrenderowany w przeglądarce** + marka docelowa + język | setki tysięcy stron (wersja z artykułu: ok. 253 tys. legit / 119 tys. phishing); CC BY 4.0, tylko do badań anty-phishingowych; podział czasowy, usunięte duplikaty, benchmarki z realistycznym odsetkiem phishingu; pole `lang` → sprawdzić liczbę stron PL/LT |
| PhiUSIIL (2024, UCI) | URL + gotowe cechy (bez kodu HTML) | 235 795 rekordów; dobry start dla modelu URL; uwaga: etykieta 1 = legit, 0 = phishing |
| Mendeley „Phishing Websites Dataset” (2021) | URL + **surowy HTML** | ok. 80 tys. (50 tys. legit / 30 tys. phishing); CC BY 4.0; dane z 2020–2021 (starsze) |
| Mendeley `fmbs4kp9wz` (2024–2025) | URL + **surowy HTML** + 70 cech | 15 358 (7 204 phishing / 8 154 legit); CC BY 4.0; legit = top-1000 stron (ryzyko: same strony główne) |
| PhishIntention / Phishpedia | zrzuty ekranu, logo, lista 277 marek | ok. 25 tys. phishing + 25 tys. legit; przydatne dla marki w treści (7.11) |

**Model treści można trenować od razu na publicznych zbiorach z kodem HTML stron** — nie czeka na scraper.

## Zasady dla danych treści

- Do treningu potrzebny jest **kod HTML strony**, a nie gotowe cechy z cudzego zbioru — cechy muszą liczyć się naszym kalkulatorem (21.2).
- Zbiory różnią się rodzajem HTML: **PhreshPhish** zawiera HTML **wyrenderowany w przeglądarce** (Selenium), zbiory z Mendeley — **surowy HTML bez JavaScriptu**. Dlatego Scraper zapisuje **dwie wersje** z jednego wejścia Playwrighta: surową odpowiedź serwera (HTML przed JavaScriptem) i wyrenderowany DOM. Model dostaje w systemie ten sam rodzaj HTML, na którym był uczony (model z PhreshPhish → wyrenderowany DOM).
- Kaggle: popularne zbiory phishingowe zawierają głównie gotowe cechy albo same URL-e, bez HTML — nie nadają się do modelu treści (mogą służyć do porównań).
- Przed użyciem każdego zbioru sprawdzamy duplikaty domen, rozkład stron głównych vs podstron, źródła stron „legit” oraz **próbkę stron pod kątem martwych** (parking, błąd, „konto zawieszone” z etykietą phishing) — dotyczy też PhreshPhish (notatnik 01 w repo TUM).