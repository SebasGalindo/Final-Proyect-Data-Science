def process_data(data):
    """
    Procesa los datos entrantes para asegurarse de que están en el formato correcto o limpiarlos antes de insertar en la base de datos.
    """
    processed = {key: value.strip() for key, value in data.items()}
    return processed
