# script-watch: auditoría de scripts de terceros

Herramienta defensiva en Python (solo librería estándar) que audita los scripts de terceros que carga una página web: cuáles son, si están protegidos con **SRI**, si la **CSP** los restringe, y si su contenido **cambió** respecto de una corrida anterior.

## Por qué existe

El 16 de noviembre de 2026, según la prensa y el investigador Scott Helme (Report URI), se detectaron archivos JavaScript manipulados en 178 organizaciones. El acceso habría venido de una vulnerabilidad en una plataforma de experimentación web de terceros (Optimizely, que confirmó el incidente y dijo haberlo corregido). El código inyectado intentaba, entre otras cosas, reemplazar direcciones de billeteras cripto y capturar datos de tarjetas.

> Antes de citar el incidente en tu propio material, leé la fuente primaria (el informe de Report URI y el comunicado del proveedor). Este README lo resume de segunda mano.

La lección para un equipo defensivo: **tu sitio ejecuta código que no controlás**. Esta herramienta hace visible esa superficie.

## Qué revisa

| ID | Hallazgo | Severidad | MITRE ATT&CK |
|----|----------|-----------|--------------|
| SW-001 | Script de terceros sin SRI (`integrity`) | Media | T1195 |
| SW-002 | Script de terceros por `http` (sin TLS) | Alta | T1195 |
| SW-003 | El hash del script cambió respecto del baseline | Alta | T1195.002 |
| SW-004 | Proveedor en tu watchlist (`--watch`) | Media | T1195.002 |
| SW-005 | Dos o más familias de patrones sospechosos (ofuscación, captura de datos, direcciones cripto) | Media | T1059.007 |
| SW-006 | Sin CSP, o CSP permisiva (`*`, `'unsafe-inline'`) | Baja / Media | T1195 |

## Uso

```bash
python -m scriptwatch https://tu-sitio.example --baseline baseline.json --save-baseline   # 1ª vez: guarda hashes
python -m scriptwatch https://tu-sitio.example --baseline baseline.json                   # luego: detecta cambios
python -m scriptwatch https://tu-sitio.example --watch optimizely --json
pytest -q
```

Salida de ejemplo (servidor local de prueba):

```
[HIGH  ] SW-002 T1195      Script de terceros sin TLS | http://localhost:8765/lib.js
[MEDIUM] SW-001 T1195      Script de terceros sin SRI | http://localhost:8765/lib.js
[MEDIUM] SW-005 T1059.007  Patrones sospechosos (heurística) | http://localhost:8765/lib.js
           Coinciden 2 familias: ofuscación, captura de datos. Puede ser un falso positivo.
[LOW   ] SW-006 T1195      Sin Content-Security-Policy | http://127.0.0.1:8765/index.html
```

## Limitaciones (importantes)

- **Análisis estático:** no ejecuta JavaScript. Los scripts que otros scripts cargan dinámicamente no se ven.
- **Los cambios de hash no distinguen** entre una actualización legítima y una manipulación. Los scripts de proveedores cambian seguido: espera ruido y revisá a mano.
- **SRI no aplica** a scripts que el proveedor modifica a propósito; marcarlos como "sin SRI" es una señal, no una prueba.
- Las heurísticas son simples y generan falsos positivos. No reemplazan una revisión de código ni un servicio de monitoreo.
- Un atacante podría servir contenido distinto según el visitante; una sola descarga no lo detectaría.
- La detección de "tercero" compara las últimas dos etiquetas del dominio (no cubre `.co.uk` y similares).

## Uso responsable

Hace un GET a la página y uno a cada script, como un navegador. Usalo sobre sitios propios, o de forma puntual sobre páginas públicas. No lo corras en masa contra terceros.

## Roadmap

- [ ] Navegador headless para ver scripts cargados dinámicamente
- [ ] Reporte PDF (reutilizando el de [incident-report-shadowentry](https://github.com/Marudm/incident-report-shadowentry))
- [ ] Integración con [MiniSOC](https://github.com/Marudm/minisoc) para alertar cambios de baseline

## Autora

Marina Della Mattia · [GitHub](https://github.com/Marudm) · [LinkedIn](https://www.linkedin.com/in/marinadellamattia/)
