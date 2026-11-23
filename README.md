# Transfer privado – blitz.cloud

Aplicación Python: sube varios archivos desde una página web con contraseña de administrador, crea enlaces de descarga aleatorios y elimina cada archivo tras 7 días.

## Publicar en blitz.cloud

1. Sube `app.py`, `Dockerfile` y `requirements.txt` a la raíz de un repositorio GitHub (el ZIP se debe **descomprimir** para subir el proyecto; no uses "Upload a website" porque es solo para webs estáticas).
2. En https://dashboard.blitz.cloud selecciona **Your own project from GitHub**, conecta GitHub y escoge el repositorio.
3. En **Advanced settings** confirma que el almacenamiento persistente / kept folders contiene `/data` (el Dockerfile declara `VOLUME ["/data"]`).
4. Despliega. Ve a **Environment** y añade `ADMIN_PASSWORD` con una contraseña **única y larga, mínimo 16 caracteres**. Reinicia la aplicación.
5. Visita la URL pública que aparece en Blitz y usa la contraseña para subir archivos.

Variables opcionales: `MAX_STORAGE_GB=0.8` y `MAX_FILE_GB=4`. Por defecto se reservan 0,8 GB para ajustarse al volumen de 1 GB que tienes en Blitz. Si amplías el volumen a 5 GB, pon `MAX_STORAGE_GB=4.5` en Environment. No basta con cambiar esta variable para ampliar el disco real.

## Seguridad / limitaciones

- Descarga mediante URL secreta aleatoria: **cualquiera que tenga el enlace puede descargar el archivo** hasta que caduque.
- Sin registro de usuarios; la subida/listado requiere `ADMIN_PASSWORD`. Nunca guardes la contraseña en GitHub ni en el código.
- Evita subir archivos sensibles sin cifrarlos antes. Los archivos en disco **no van cifrados por esta app**.
- Al dormir la app, el proceso Python se detiene: los archivos vencidos se borran al despertar y cuando el proceso esté activo, no necesariamente al segundo exacto de cumplirse 7 días.
- El plan gratuito de Blitz no hace copias de seguridad de los volúmenes. Se puede descargar lo guardado desde Files en el panel.
- Los archivos en subida no se ofrecen hasta estar completos. El navegador puede tener restricciones de tamaño/tiempo de subida y el proveedor puede imponer otras adicionales.
- Si otro proceso edita los archivos del volumen o se ejecutan múltiples instancias, la cuota calculada no está diseñada para ser coordinada entre instancias.
- No hay protección avanzada contra fuerza bruta/DDoS: usa una contraseña robusta y no difundas la página de administración.

## Prueba local

```bash
pip install -r requirements.txt
# Linux/macOS
export ADMIN_PASSWORD='una-clave-muy-larga-y-unica'
export DATA_DIR='./data'
python app.py
```

En Windows PowerShell:

```powershell
$env:ADMIN_PASSWORD='una-clave-muy-larga-y-unica'
$env:DATA_DIR='./data'
python app.py
```

Abre http://127.0.0.1:8080

## Actualizar desde GitHub (sin perder archivos)

1. Descomprime el ZIP. En https://github.com/santolv/transfernow pulsa **Add file → Upload files**.
2. Sube `app.py`, `Dockerfile`, `requirements.txt` y `README.md` a la **raíz** del repositorio; confirma **Commit changes**.
3. En Blitz pulsa **Build the newest code** si no se despliega automáticamente.
4. **No borres la aplicación ni el volumen persistente `/data`**: ahí están los enlaces y archivos existentes.

La web divide cada archivo en trozos de 8 MB (`/api/start`, `/api/chunk/<id>`, `/api/finish/<id>`). Cada petición queda por debajo de 100 MB; muestra progreso y reintenta fragmentos fallidos. Los uploads sin terminar se borran después de 6 horas al ejecutarse la limpieza. Si la aplicación duerme, esa limpieza ocurre al despertar. La contraseña `ADMIN_PASSWORD` debe seguir definida en Blitz (no la subas a GitHub).
