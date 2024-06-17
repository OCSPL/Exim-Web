from app import EximExport, EximImport


def get_column_choices(search_type):
    if search_type == 'export':
        return [(column.name, column.name) for column in EximExport.__table__.columns]
    else:
        return [(column.name, column.name) for column in EximImport.__table__.columns]
