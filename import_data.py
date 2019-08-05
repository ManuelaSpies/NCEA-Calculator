# Queries to create tables

create_table_standard = """CREATE TABLE IF NOT EXISTS standard(
                            standard_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            standard_name INTEGER NOT NULL,
                            description TEXT NOT NULL,
                            credits INTEGER NOT NULL,
                            ncea_level INTEGER NOT NULL,
                            reading TEXT NOT NULL,
                            writing TEXT NOT NULL,
                            literacy TEXT NOT NULL,
                            numeracy TEXT NOT NULL,
                            ue_credits TEXT NOT NULL,
                            standard_user INTEGER NOT NULL,
                            FOREIGN KEY(standard_user) REFERENCES user(user_id)
                            );
                            """

create_table_result = """CREATE TABLE IF NOT EXISTS result(
                            entry_id integer PRIMARY KEY AUTOINCREMENT,
                            as_id integer NOT NULL,
                            grade text NOT NULL,
                            result_user INTEGER NOT NULL,
                            FOREIGN KEY(result_user) REFERENCES user(user_id)
                            );
                            """

create_table_user = """CREATE TABLE IF NOT EXISTS user(
                        user_id integer PRIMARY KEY AUTOINCREMENT,
                        username text UNIQUE NOT NULL,
                        password text NOT NULL
                        );"""

# Queries to insert test data
test_data_standard = """INSERT INTO standard (standard_id, standard_name, description,  credits, ncea_level, reading, 
                        writing, numeracy, literacy, ue_credits, standard_user)
                        VALUES (NULL, 91367,
                        'Demonstrate understanding of advanced concepts relating to managing shared information within information systems.',
                        3, 2, 'Yes', 'No', 'Yes', 'No', 'No', 1), 
                        (NULL, 91215, 'Discuss a drama or theatre form or period with reference to a text.', 
                        4, 2, 'Yes', 'No', 'Yes', 'Yes', 'Yes', 1),
                        (NULL, 91101, 'Produce a selection of crafted and controlled writing', 
                        6, 2, 'Yes', 'No', 'Yes', 'No', 'Yes', 1);"""
test_data_result = """INSERT INTO result (entry_id, as_id, grade, result_user) 
                        VALUES(NULL, 91215, 'M', 1), (NULL, 91367, 'E', 1);"""
test_data_user = """INSERT INTO user (user_id, username, password)
                    VALUES (NULL, 'testuser1', 'test1'), (NULL, 'testuser2', 'test2');"""

# Queries to count table rows
count_rows_standard = """SELECT COUNT(*) FROM standard;"""
count_rows_result = """SELECT COUNT(*) FROM result;"""
count_rows_user = """SELECT COUNT(*) FROM user;"""
count_rows_standard_user = """SELECT COUNT(*) FROM standard 
                              WHERE standard_user = ?;"""

count_rows_credit_entry = """SELECT COUNT(*)
                        FROM standard
                        WHERE standard_name = ?
                        AND standard_user = ?;"""
count_rows_new_entry = """SELECT COUNT(*)
                          FROM result
                          WHERE as_id = ?
                          AND result_user = ?;"""
count_rows_username = """SELECT COUNT(*) FROM user 
                          WHERE username = ?"""

# Get Credits queries
get_credits_all_query = """SELECT credits, grade
            FROM result JOIN standard
            ON as_id = standard_name
            WHERE result_user = ?;"""
get_credits_l3_query = """SELECT credits, grade
            FROM result JOIN standard
            ON as_id = standard_name
            AND ncea_level = 3
            AND result_user = ?;"""
get_credits_12_query = """SELECT credits, grade
            FROM result JOIN standard
            ON as_id = standard_name
            AND ncea_level = 2
            AND result_user = ?;"""
get_credits_l1_query = """SELECT credits, grade
            FROM result JOIN standard
            ON as_id = standard_name
            AND ncea_level = 1
            AND result_user = ?;"""

get_all_done_standards = """SELECT standard_id, grade, standard_name, description, credits, ncea_level,numeracy, literacy,  reading, writing, ue_credits
                            FROM standard JOIN result
                            on as_id = standard_name
                            AND standard_user = ?;"""

get_all_standard_names = """SELECT standard_name, description
                            FROM standard
                            WHERE standard_user = ?;"""

get_all_lit_num_things = """SELECT credits, literacy, numeracy, reading, writing
                            FROM standard JOIN result
                            WHERE as_id = standard_name
                            AND (reading = "Yes"
                            OR writing = "Yes"
                            OR numeracy = "Yes"
                            OR literacy = "Yes")
                            AND standard_user = ?;"""

# Enter data queries
new_credit_entry_query = """INSERT INTO result(entry_id, as_id, grade, result_user)
                            VALUES(NULL, ?, ?, ?);"""
new_standard_entry_query = """INSERT INTO standard(standard_id, standard_name, description, credits, ncea_level, 
                              reading, writing, literacy, numeracy, ue_credits, standard_user)
                              VALUES(NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"""

# User Related Queries
create_user = """INSERT INTO user(user_id, username, password) 
                VALUES (NULL,?,?);"""
find_user = """SELECT user_id, username, password
                FROM user
                WHERE username = ?;"""

setting_change_password = """UPDATE user SET password = ? WHERE user_id = ?;"""
setting_change_username = """UPDATE user SET username = ? WHERE user_id = ?;"""

delete_account_result = """DELETE FROM result WHERE result_user = ?;"""
delete_account_standard = """DELETE FROM standard WHERE standard_user = ?;"""
delete_account_user = """DELETE FROM user WHERE user_id = ?;"""
