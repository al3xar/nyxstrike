# Tool selector con TypeSafe (System One / Jev) — diseño

- **Fecha:** 2026-09-23
- **Repo:** `nyxstrike`
- **Estado:** aprobado, en implementación
- **Alcance:** paso A del brainstorming — *elegir la siguiente herramienta dentro de una fase*.

## Contexto

Hoy la selección de herramienta por fase la razona un LLM agéntico en prosa,
apoyado en la tabla de prioridades de `AI/agents/**/shared/tool-policy.md` y en el
registro tipado `tool_registry.py` (cada herramienta con `desc`, `category`,
`effectiveness` 0–1).

El repo **ya tiene** el andamiaje de decisión que este diseño necesita, anclado al
TFM (ADR `hades-tfm/wiki/nyxstrike/adr-router-decision-indexado.md`, spike T-24):

- `backend/server_core/intelligence/router.py` — router v1. **Nivel 0
  determinista** decide en producción con el ranking precision-first
  (`effective_score`), emite `Decision(tool, confidence, reason, level, escalated,
  index)` y calibra la confianza por margen (patrón 1.0 / 0.75 / 0.5 de
  `classify_intent`). **Nivel 1**: un modelo pequeño actúa **solo como gate de
  escalación** cuando la confianza determinista cae por debajo de `~0.6`
  (`ROUTER_CONFIDENCE_THRESHOLD`), con la elección **validada contra el shortlist
  ofrecido** (disciplina `validate_choice`: `choice in allowed`). Fuera de conjunto
  / abstención / error ⇒ se mantiene el top-1 determinista.
- Interfaz de extensión documentada: `RouterModel.route(state) -> Decision | None`.
  El fallback existente `PromptFallbackRouter` usa **texto libre**.
- Inyección por sesión vía `PlanAndApproveController.configure_router(session_id,
  enabled, model)`; con router activo se registra un `router_decision` auditable en
  el `run_log`. OFF por defecto (aditivo).

Esta filosofía —determinista decide, el modelo solo interviene en baja confianza y
restringido a un conjunto— coincide **exactamente** con la guía de System One de
TypeSafe (routing por confianza; el código es dueño del control de flujo). Jev es,
de hecho, el nombre que el TFM ya usa para ese modelo de juicio.

## Decisión de diseño

**No** se añade un `tool_selector.py` nuevo en la raíz (duplicaría la disciplina del
router). En su lugar se implementa un `RouterModel` respaldado por TypeSafe que
sustituye el juicio en texto libre del `PromptFallbackRouter` por un `Choice`
tipado. Todo lo demás (gate de umbral, validación contra el shortlist, auditoría,
composición con `effective_score`) se reutiliza sin tocar.

### Componente: `JevRouterModel` (`backend/server_core/intelligence/router_jev.py`)

`RouterModel` nivel-1 (`name = "jev-typesafe-v1"`). Contrato:

1. `candidates = _candidates_from_state(state)` (helper reutilizado de `router.py`).
   Sin candidatos ⇒ `None` (abstención).
2. `criteria = {tool: desc}` donde `desc` sale de `tool_registry.get_tool(tool)`
   (fuente de verdad única; la tabla markdown queda como documentación humana).
3. Un `Choice` en una sola request `system_one`:
   - `state`: `state_text`, `phase` y `tools_already_run` tomados del `state` del
     router (`context.tools_run` si está presente).
   - `instructions`: "Dado el estado del engagement y la fase, ¿qué herramienta es
     el mejor siguiente paso? Elige exactamente una opción del conjunto ofrecido, o
     `advance_phase` si ninguna aporta señal útil."
   - `criteria`: el mapa `tool -> desc` **más la opción de escape `advance_phase`**
     (el "none-of-these" de los docs de TypeSafe), activable/desactivable con el
     flag `allow_advance_phase` (por defecto `True`).
4. Se lee `choice` y `confidence` de la respuesta. **`choice ∉ allowed` ⇒ `None`**
   (aunque el `DeterministicRouterModel` revalida, el fallback se abstiene por su
   cuenta). `allowed` incluye `advance_phase` cuando está habilitado.
5. Devuelve una `Decision` nivel-1 escalada:
   - herramienta: `Decision(tool=choice, ..., index=_index_of(...), action=None)`;
   - escape: `Decision(tool=None, index=None, action="advance_phase", ...)`.

### Acción no-herramienta: `advance_phase`

`router.py` define la constante `ADVANCE_PHASE = "advance_phase"` y la dataclass
`Decision` gana el campo **`action: Optional[str] = None`** (retrocompatible: las
decisiones de herramienta lo dejan en `None`). Semántica: el router **decide** la
acción; el supervisor / state-machine de los agentes **actúa** (avanza de fase) —
el router nunca ejecuta ni avanza por su cuenta, igual que con `Decision.tool`.

El gate de `DeterministicRouterModel` acepta del fallback una decisión con
`action == ADVANCE_PHASE` igual que una herramienta en conjunto, sujeta al mismo
umbral de confianza. Nivel 0 nunca emite `advance_phase` (solo rankea herramientas).
La entrada `router_decision` del `run_log` incluye `action` para auditoría.

**Inyectabilidad / degradación:** la llamada al SDK vive tras un `judge_fn`
inyectable — `judge_fn(state_text, criteria, state) -> (choice, confidence)`. El
`judge_fn` por defecto importa `typesafe_sdk` de forma perezosa y construye el
cliente (la API key la lee el SDK de `TYPESAFE_API_KEY`, nunca se guarda en config).
Si el SDK no está instalado, la key falta o hay timeout/red ⇒ **excepción capturada
⇒ `None`** ⇒ se mantiene el top-1 determinista. El pipeline nunca se bloquea.

**Composición con `effectiveness`:** ya resuelta aguas arriba — los `candidates`
llegan rankeados por `effective_score` (que incorpora `effectiveness`). No se mezcla
el prior dentro del prompt: el juicio de Jev queda crudo y reutilizable, y el código
(el gate determinista) decide si se acepta.

**Wiring (opt-in):** helper `make_jev_router(threshold=0.6)` que devuelve
`DeterministicRouterModel(fallback=JevRouterModel(), threshold=threshold)`. Se activa
por sesión con `controller.configure_router(sid, enabled=True, model=make_jev_router())`.

### Config (`config.py`, leída vía `config_core.get`)

- `TYPESAFE_MODEL` (`"jev"`) — modelo System One.
- `TYPESAFE_ROUTER_ENABLED` (`False`) — opt-in del fallback Jev del router.
- `TYPESAFE_TIMEOUT` (`30`) — segundos.
- La API key **no** se guarda en config: el SDK la lee de `TYPESAFE_API_KEY` (secreto
  server-side, fuera de cualquier `.env` de cluster).

### Dependencia

`typesafe-sdk` como extra opcional (`[project.optional-dependencies].ai`) para que el
grueso del repo y los tests corran sin la dependencia.

## Manejo de errores

| Situación | Comportamiento |
|-----------|----------------|
| Sin candidatos | `None` (abstención) → el gate marca "supervisor must act" |
| SDK ausente / key ausente / timeout / red | excepción capturada → `None` → top-1 determinista |
| `choice` fuera del shortlist | `None` (disciplina `validate_choice`) |
| Confianza de Jev < umbral | el gate determinista mantiene el top-1 (Jev no decide solo) |
| Jev elige `advance_phase` (≥ umbral) | `Decision(action="advance_phase", tool=None)` → el supervisor avanza de fase |
| `advance_phase` con confianza < umbral | el gate mantiene el top-1 determinista |

## Pruebas (`tests/test_router_jev.py`, offline)

Sin SDK ni red — `judge_fn` y `describe` inyectados:

- elección en conjunto con confianza alta → `Decision` nivel-1, `tool`/`index`/`model`
  correctos;
- `choice` fuera del shortlist → `None`;
- `judge_fn` lanza excepción → `None`;
- sin candidatos → `None`;
- integración con `DeterministicRouterModel(fallback=JevRouterModel(...))`: consulta a
  Jev solo por debajo del umbral, acepta en conjunto, respeta la revalidación;
- `criteria` se construye a partir de `desc` del registro (no duplica la tabla);
- **`advance_phase`**: se ofrece en `criteria`; Jev lo elige → `Decision` con
  `action="advance_phase"` (`tool`/`index` = `None`); el gate lo acepta bajo umbral y
  lo rechaza si la confianza es baja; `allow_advance_phase=False` lo retira del
  conjunto; `to_dict()` transporta `action`.

Se valida el **comportamiento** (qué herramienta/acción se elige y cuándo se abstiene),
no solo el tipo de salida. La suite existente (`test_router.py`, `test_plan_and_approve.py`)
sigue verde: `action` es aditivo (default `None`) y el gate cae a la comprobación de
herramienta cuando no hay acción.

## No incluido (YAGNI)

- No se descompone aún en juicios atómicos `Noul`/`Score` por fase (enfoque 2 del
  brainstorming): se deja para las fases VULN cuando el patrón base esté validado.
- El router **no ejecuta** el avance de fase: emite la señal `advance_phase` auditada y
  el supervisor/state-machine de los agentes la consume. `propose_next_step` solo gana
  el campo aditivo `action` en la entrada `router_decision` del `run_log`.
