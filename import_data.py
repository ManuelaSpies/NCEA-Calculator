# Queries to create tables

create_table_standard = """CREATE TABLE IF NOT EXISTS standard(
                            standard_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            standard_name INTEGER NOT NULL,
                            description TEXT NOT NULL,
                            credits INTEGER NOT NULL,
                            ncea_level INTEGER NOT NULL,
                            lit_reading INTEGER NOT NULL,
                            lit_writing INTEGER NOT NULL,
                            numeracy INTEGER NOT NULL,
                            ue_credits INTEGER NOT NULL
                            );
                            """
create_table_result = """CREATE TABLE IF NOT EXISTS result(
                            entry_id integer PRIMARY KEY AUTOINCREMENT,
                            as_id integer NOT NULL UNIQUE,
                            grade text NOT NULL);
                            """

# Queries to import data


# Get Credits queries
get_credits_all_query = """SELECT credits, grade
            FROM result JOIN standard
            ON as_id = standard_name;"""
get_credits_l3_query = """SELECT credits, grade
            FROM result JOIN standard
            ON as_id = standard_name
            AND ncea_level = 3;"""
get_credits_12_query = """SELECT credits, grade
            FROM result JOIN standard
            ON as_id = standard_name
            AND ncea_level = 2;"""
get_credits_l1_query = """SELECT credits, grade
            FROM result JOIN standard
            ON as_id = standard_name
            AND ncea_level = 1;"""