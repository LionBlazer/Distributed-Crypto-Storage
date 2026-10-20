# Distributed Crypto Storage

## Project context

This project aims to build distributed encrypted SQL storage on participant-owned
computers, following [REQUIREMENTS.md](REQUIREMENTS.md). Peers should store encrypted
data and process queries without access to plaintext. The requirements cover FHE,
SQL operations, bounded storage and memory, replication, recovery, malicious peers,
and verifiable query results.

The repository contains local Rust/Cargo BFV and TFHE FHE prototypes, alongside
requirements and research. The prototype experiments with a fixed encrypted schema;
it does not establish the feasibility of distributed SQL or query proofs. Production
cryptography, consensus, and rewards remain open choices. Treat performance and
resource numbers as targets to validate, not established capabilities. Do not assume
that blockchain is required.

## Requirements are the implementation contract

- Every feature, prototype, optimization, UI action and agent subtask must follow
  the requirements below. Read this contract and `REQUIREMENTS.md` before changing
  the relevant behavior. A prototype may implement part of the system, but it must
  identify unmet requirements and must not replace required behavior with a shortcut.
- SQL processing on peers must use homomorphic encrypted operations and return
  encrypted results for client-side completion. Plaintext query execution, answers
  calculated from owner fixtures, simulated answers, echoed inputs or dummy
  cryptographic work are not substitutes for the required computation. Client
  decryption of the completed encrypted result is allowed. Keep fixture inspection
  and simulation controls separate from actual query execution.
- Do not silently weaken confidentiality, decentralization, integrity, freshness,
  proof, resource or failure guarantees to make a feature appear complete or faster.
  Record a technical blocker and investigate a compliant implementation. Changes to
  the requirements or an alternative that relaxes them need explicit user direction.
- Treat resource/performance numbers as targets until the complete relevant
  operation is measured. FHE encryption alone does not establish a computation proof,
  and local manager behavior does not establish decentralized agreement.

### Keep the two copies synchronized

`REQUIREMENTS.md` is the canonical requirements text. The block between
`requirements:begin` and `requirements:end` below mirrors its full requirements
section, including context and unresolved decisions; the research-source appendix
stays in `REQUIREMENTS.md`. Preserve the original Russian wording.

Whenever requirements change, update both copies in the same logical change.
Before implementation and before completion, compare them. If they differ,
reconcile them using the latest explicit user instructions and Git history before
continuing dependent implementation; do not overwrite conflicting intent blindly.
The `requirements_sync` test rejects a mismatch:

```sh
cargo test --release --locked -p repository-contracts --test requirements_sync
```

<!-- requirements:begin -->
# Требования к распределённой зашифрованной SQL-базе

Хотим получить распределённую зашифрованную SQL-базу на домашних компьютерах участников. Заказчик один и владеет базой; пиры поддерживают инфраструктуру и могут обращаться к базе как клиенты в пределах предоставленных прав.

Статус: целевые требования. Их совместную достижимость, скорость и потребление ресурсов ещё нужно проверить. Конкретные протоколы и библиотеки пока не выбраны.

1. **Без центрального сервера.** Хранение, поиск, вычисления и согласование изменений распределены между пирами. Выход одного узла не останавливает систему. Новые пиры могут свободно подключаться без приглашения; число идентификаторов само по себе не должно давать дополнительный вес при согласовании состояния. Согласование состояния не должно зависеть от сторонней сети. Для финализации принимаем модель: менее 1/3 подтверждённого вычислительного веса может быть злонамеренным. Без необходимого кворума выдача блокировок должна ждать; разделение сети не должно приводить к двум конфликтующим окончательным блокировкам.

2. **Конфиденциальность хранения и вычислений.** Пиры хранят зашифрованные данные и выполняют FHE-вычисления без доступа к открытому содержимому. Секретные ключи расшифрования остаются у владельца базы или его приложения. Условие WHERE и его константы также должны оставаться скрытыми от пиров.

3. **Обычная работа с базой.** Создание баз и таблиц, чтение, добавление, изменение и удаление записей, индексы и транзакции. Конечная цель — полноценный SQL; набор функций первой версии определим отдельно.

4. **Компактное хранение на диске.** Целевой размер — около 1–2× исходных данных без учёта репликации, индексов и служебных данных. Обновления не должны приводить к постоянному разрастанию базы.

5. **Обработка частями.** В FHE разворачиваются только данные, необходимые для операции. Где запрос и выбранная модель приватности допускают индекс, система должна обходиться без перебора всей таблицы.

6. **Ограниченные ресурсы пира.** Цель — 1–2 ГБ RAM на весь процесс, включая ключи, временные результаты и кэш. Дисковую квоту задаёт участник; рассматриваем 10, 20 и 30 ГБ. Базовая работа — на CPU, GPU может ускорять вычисления.

7. **Распределение нагрузки.** Каждый пир хранит часть базы. При выборе исполнителей учитываются доступность, задержка связи и свободные ресурсы. Ориентиры масштаба — 10 тысяч, 100 тысяч и миллион пиров.

8. **Сохранность данных.** Копии размещаются в независимых группах отказа. Система отслеживает исчезновение пиров и автоматически восстанавливает недостающие копии. Требуемый запас устойчивости к массовым отключениям нужно определить численно.

9. **Авторизация и целостность данных.** Изменения разрешены только авторизованным пользователям. Подмена хранимых данных должна обнаруживаться.

10. **Практичная скорость.** Цель — интерактивная работа приложения. Допустимые задержки и пропускную способность зафиксируем на конкретных запросах и объёмах данных.

11. **Проверка ответа одного пира.** Ответ одного пира принимается только с действительным криптографическим доказательством правильности и полноты результата: подходящие записи не пропущены. Доказательство связано с конкретным запросом и подтверждённой согласованной версией базы.

12. **Проверка доказательства.** Проверка должна быть быстрой, без повторного выполнения запроса и сравнения ответов нескольких пиров. Успешная расшифровка, обычная контрольная сумма или подпись отвечающего пира сами по себе не доказывают правильность результата.

13. **Актуальность ответа.** Актуальность версии проверяется отдельно от правильности вычисления. Ответ на устаревших данных отклоняется, если запрос требует более свежей версии.

14. **Опционально: вознаграждения пиров.** Если вознаграждения включены, обязательны пункты 15–17. Децентрализованный протокол оплачивает подтверждённое хранение, вычисления и внутреннюю работу сети, включая восстановление и перераспределение копий.

15. **Полезные задания.** Необходимость внутренней работы определяется протоколом по согласованному состоянию сети. Пиры автоматически выбирают выгодные задания с учётом своих ресурсов, затрат и правил размещения данных.

16. **Цена при дефиците.** При дефиците копий или ресурсов цена соответствующих новых заданий автоматически повышается в пределах заданного бюджета и снижается после устранения дефицита.

17. **Защита от накруток.** Проверки и учёт должны предотвращать фиктивные и повторные начисления. Правила вознаграждений должны противодействовать сговору и заработку на искусственно созданном дефиците.

Остаётся определить: допустимые утечки об обращениях, протокол подтверждения вычислительного веса и детали отказов и восстановления, требуемую свежесть данных, задержки и SQL первого прототипа. Токен, платёжный механизм и экономические параметры пока не выбраны; необходимость блокчейна разберём отдельно.
<!-- requirements:end -->

## Working conventions

- Keep reusable libraries in `crates/`, production process entry points in `apps/`,
  GUI/test adapters in `playground/`, and measurement executables or research
  candidates in `experiments/`. Core
  libraries must not depend on either consumer layer, GUI frameworks, virtual
  time, presets or fixture generators. Keep tests at their owning boundary.
  Cargo default members must build core only. Do not promote local manager or
  unverified experimental behavior into production guarantees by renaming it.

- Live GUI storage/query behavior must use independently running peer processes
  over peer-transport/peer-runtime. Do not reintroduce DemoNetwork, LabEngine or
  an in-process evaluator as a live fallback. Historical local libraries are
  research/test consumers only. Network observations must come from actual I/O.
- Never accept a network SQL answer or commit its mutation without the required
  computation/completeness proof and fresh agreed head. Missing proof is a hard
  rejection, not permission to treat TLS, hashes or decryption as verification.

- Respond to the user in Russian. Write new project documentation, code, and commit
  messages in English unless requested otherwise. Preserve the imported Russian
  REQUIREMENTS.md and its sources; change requirements only within the requested scope.
- Work in this checkout using ordinary Git branches. Do not create worktrees unless
  the user requests one. Preserve unrelated files, staged changes, and commits.
- Before implementation, read the relevant requirements and existing code. Record
  unresolved technical choices instead of silently presenting them as settled.
- Keep module ownership and dependencies clear. Do not introduce compatibility
  layers or migrations unless requested.
- Never commit credentials, secret keys, participant data, local database contents,
  or generated outputs. Public test fixtures must be explicitly non-secret.

## Branch selection

The integration branch is `master`; the remote is `origin`:
`git@github.com:LionBlazer/Distributed-Crypto-Storage.git`.

Before a new implementation or documentation task, use
[task-branch](.agents/skills/task-branch/SKILL.md). Create a short
`codex/feature/<topic>`, `codex/fix/<topic>`, `codex/docs/<topic>`, or
`codex/chore/<topic>` branch from freshly fetched `origin/master` when on master
or on an already integrated branch. Continue related unfinished work in its branch.
Explicit user instructions about the branch override this default. Initial repository
setup is explicitly authorized to commit and push directly to master.

## Commit, push, and synchronization

**After every completed, validated logical change, commit and push automatically.**
This includes small fixes, documentation, configuration, and skill changes; do not
wait until a change is substantial or for another request to publish it. Group edits
that form one coherent change, rather than committing every intermediate file save.
Explicit read-only, no-commit, or no-push instructions take precedence.

Use [commit-and-push](.agents/skills/commit-and-push/SKILL.md). Stage explicit task
paths and inspect the staged diff before committing. Use Conventional Commits such
as `feat(storage): add shard allocation` or `docs: clarify query proof requirements`.
Commit only completed task changes. Never stash, reset, discard, or unstage unrelated
work to make publication easier.

Push normally to the same named branch with an explicit destination. Do not force
push or rewrite published history without explicit authorization. If the remote
branch advanced, fetch, inspect both histories, merge compatible changes, validate
the combined result, and retry normally. Stop after repeated concurrent updates or
when conflict intent cannot be established.

After a successful task-branch push, fetch remote master and merge `origin/master`
into that same working branch. If this changes the branch, validate and push again.
Perform one such synchronization cycle; its follow-up push does not start another.
When working directly on master by explicit request, synchronize against remote
master before its push and verify the result afterwards.

Promoting a task branch into master is a separate operation. Use
[merge-to-master](.agents/skills/merge-to-master/SKILL.md) only when the user invokes
it or requests promotion. That request authorizes review, necessary fixes, merge,
normal push to master, and returning this checkout to master without another generic
confirmation. Ordinary task completion publishes only the task branch.

## Verification and completion

Use the project's actual build and test commands once they exist. Until then, check
document links, skill frontmatter, diffs, and requirements consistency; do not invent
a build command or describe documentation checks as application tests.

For implementation changes, test the observable behavior at the owning boundary.
For distributed or cryptographic changes, cover the affected failure model,
authorization, version freshness, proof rejection, or resource limit as relevant.
Performance claims require reproducible measurements of the full operation.

Keep test feedback fast. Choose the smallest meaningful checks at the owning
boundary and optimize expensive setup, repeated verification and unnecessary
serialization. Profile slow scenarios by preparation, proving, verification,
transport/consensus waiting and recovery; do not assume their whole duration is
unavoidable cryptographic cost. Where the protocol permits, proceed after one
independently valid quorum certificate instead of waiting for every peer.
Run expensive multi-process and recovery gates when the affected boundary changes
or an unresolved failure requires them; repeat or broaden passed checks only for
new changes, failures or concrete concerns. Reuse bounded public test setup only
when isolation and failure coverage are preserved. Never shorten tests by weakening
proofs, freshness, authorization, failure/resource guarantees or meaningful
assertions, substituting simulated computation, or relaxing production timeouts.
Measure improvements on comparable complete operations and report remaining costs.

Keep repository contract guards dependency-free to avoid GUI and cryptographic
builds.

Report the change, relevant verification, final branch and commit, and whether push
and master synchronization succeeded. State concrete blockers accurately.

## Project skills

Keep shared skills in `.agents/skills/`. They are adapted from SpaceTimeAutocoder2
for this repository and do not select its technology stack.

- [task-branch](.agents/skills/task-branch/SKILL.md): select or create a working branch.
- [commit-and-push](.agents/skills/commit-and-push/SKILL.md): publish each completed change and incorporate remote master.
- [merge-to-master](.agents/skills/merge-to-master/SKILL.md): review and promote an explicitly requested branch.
- [readable-test-design](.agents/skills/readable-test-design/SKILL.md): test observable behavior at the right boundary.
- [library-api-structure](.agents/skills/library-api-structure/SKILL.md): separate reusable contracts from implementation.
- [reusable-library-extraction](.agents/skills/reusable-library-extraction/SKILL.md): extract capabilities with clear ownership.
- [document-modules](.agents/skills/document-modules/SKILL.md): document actual module responsibilities and dependencies.
