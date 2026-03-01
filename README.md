# 🔐 SecureLab - Ethical Hacking Login Platform

Plataforma educativa para practicar técnicas de hacking ético enfocada en autenticación.

---

## Requisitos

```bash
pip install flask
```

## Iniciar el servidor

```bash
cd ethical_hacking_lab
python app.py
```

El servidor correrá en `http://127.0.0.1:5000`

---

## Credenciales del Lab

| Usuario    | Contraseña     | Rol   |
|------------|----------------|-------|
| admin      | secretpass123  | Admin |
| usuario1   | password456    | User  |

---

## Páginas disponibles

| URL             | Descripción                        |
|-----------------|------------------------------------|
| `/login`        | Página de login (objetivo de ataque) |
| `/dashboard`    | Panel del usuario autenticado      |
| `/logs`         | Panel admin - logs de ataque       |
| `/api/logs`     | API JSON de los logs               |
| `/api/status`   | Health check del servidor          |

---

## Funcionalidades

- ✅ Login con usuario y contraseña
- ✅ Logging de TODOS los intentos (usuario, contraseña, IP, User-Agent)
- ✅ Bloqueo automático después de 5 intentos fallidos
- ✅ Temporizador de desbloqueo (5 minutos)
- ✅ Panel admin con estadísticas en tiempo real
- ✅ API REST para consultar logs externamente
- ✅ Auto-refresh en panel de logs

---

## Herramientas de ataque sugeridas

### 1. Hydra (Brute Force)
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 http-post-form "/login:username=^USER^&password=^PASS^:Credenciales incorrectas"
```

### 2. Burp Suite
- Configura el proxy en localhost:8080
- Captura la petición POST de /login
- Envía al Intruder para ataques de diccionario

### 3. cURL manual
```bash
curl -X POST http://127.0.0.1:5000/login \
  -d "username=admin&password=test123" \
  -v
```

### 4. Python script
```python
import requests

passwords = ["123456", "password", "admin", "secretpass123"]
for pwd in passwords:
    r = requests.post("http://127.0.0.1:5000/login",
                      data={"username": "admin", "password": pwd})
    print(f"{pwd} -> {r.status_code}")
```

---

## Escalado futuro (Roadmap)

### Fase 2 - Vulnerabilidades adicionales
- [ ] SQL Injection en el login
- [ ] XSS reflejado en parámetros
- [ ] CSRF sin protección

### Fase 3 - Base de datos real
- [ ] Migrar a SQLite/PostgreSQL con SQLAlchemy
- [ ] Practicar SQL injection real

### Fase 4 - Más features de seguridad
- [ ] 2FA (Two-Factor Authentication)
- [ ] CAPTCHA
- [ ] Rate limiting con Flask-Limiter
- [ ] Tokens JWT
- [ ] Headers de seguridad (CSP, HSTS, etc.)

### Fase 5 - Red Team completa
- [ ] Dockerizar la aplicación
- [ ] Múltiples servicios vulnerables
- [ ] Scoring system para CTF
