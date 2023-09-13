# Imagen base de Python
FROM python:3.11

# Directorio de trabajo 
WORKDIR /app

# Archivos requeridos
COPY . /app/


# Instalación de las dependencias
RUN pip install -r requirements.txt

# Puerto aplicación Flask
EXPOSE 5000

# Aplicación Flask
CMD ["python", "app.py"]
