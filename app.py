from flask import Flask, render_template, request, redirect, session
import sqlite3
from sqlite3 import Error
from import_data import *
from import_messages import *
from flask_bcrypt import Bcrypt

DATABASE_NAME = "credit.db"

app = Flask(__name__)

flask_bcrypt = Bcrypt(app)

app.secret_key = "コレは秘密다. Jingle bells Käsekuchen. 4729371927"


def is_logged_in():
    # initialise_tables(create_connection(DATABASE_NAME))
    try:
        print("Session:", session['username'])
        return session['user_id'] != ""
    except KeyError:
        print("Not logged in")
        return False


def create_connection(db_file):
    """create a connection to the sqlite db"""
    try:
        connection = sqlite3.connect(db_file)
        initialise_tables(connection)
        return connection
    except Error as e:
        print(e)

    print("STATUS: create_connection completed.")
    return None


def execute_query(con, query):
    """executes query into database."""
    if con is not None:
        try:
            c = con.cursor()
            return c.execute(query)
        except Error as e:
            print(e)
    else:
        print("ERROR: No connection in execute_query().")


def initialise_tables(con):
    """creates tables and enters initial values."""
    # Creates Tables
    execute_query(con, create_table_user)
    execute_query(con, create_table_standard)
    execute_query(con, create_table_result)

    print("STATUS: initialise_tables() completed.")


def get_credits(name, query):
    """counts and sorts all existing credits by grade."""
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    cur.execute(query, (session['user_id'],))
    entries = cur.fetchall()

    e_total = 0
    m_total = 0
    a_total = 0

    for standard in entries:
        if standard[1] == "E":
            e_total += standard[0]
        elif standard[1] == "M":
            m_total += standard[0]
        elif standard[1] == "A":
            a_total += standard[0]

    if name == "Level 1":
        goal = 80
    elif name == "All":
        goal = 0
    else:
        goal = 60

    total = e_total + m_total + a_total
    if total < goal:
        left = goal - e_total - m_total - a_total
    else:
        left = 0

    print("STATUS: get_credits completed for {}.".format(name))
    return [name, total, e_total, m_total, a_total, left]


def credits_numbers():
    all_credits = get_credits("All", get_credits_all_query)
    l3_credits = get_credits("Level 3", get_credits_l3_query)
    l2_credits = get_credits("Level 2", get_credits_12_query)
    l1_credits = get_credits("Level 1", get_credits_l1_query)

    all_credits.append('all')
    l3_credits.append('l3')
    l2_credits.append('l2')
    l1_credits.append('l1')

    return [all_credits, l3_credits, l2_credits, l1_credits]


def get_categories(data, number):
    outcome = 0
    for standard in data:
        if standard[number] == "Yes":
            outcome += standard[0]

    return outcome


@app.route('/')
def main():
    if is_logged_in():
        credits_package = credits_numbers()
        # Credit's Package: [[all [name, total, e, m, a, left, codename (all/l3/...)], l3, l2, l1]

        return render_template("home.html", results=credits_package, logged_in=is_logged_in(), session=session)

    else:
        return redirect('/login')


@app.route('/login')
def login_page(message=False, colour="light"):
    if is_logged_in():
        return redirect('/')
    return render_template("login.html", message=message, colour=colour)


@app.route('/contact')
def contact():
    if is_logged_in():
        base = "base.html"
    else:
        base = "nologin_base.html"
    return render_template("contact.html", session=session, base=base)


@app.route('/gallery')
def gallery():
    if is_logged_in():
        base = "base.html"
    else:
        base = "nologin_base.html"
    return render_template("gallery.html", session=session, base=base)


@app.route('/overview')
def overview():
    if not is_logged_in():
        return login_page(not_logged_in, "primary")

    # LIST OF ALL COMPLETED STANDARDS
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    cur.execute(get_all_done_standards, (session['user_id'],))
    standards = cur.fetchall()

    # LIST OF ALL CREDITS BY GRADE / LEVEL
    credits_package = credits_numbers()

    # LEVEL ENDORSEMENT ["level", To E Endorsement, To M Endorsement]
    endorsement_data = [["l3", 50-credits_package[1][2], 50-credits_package[1][3]-credits_package[1][2]],
                        ["l2", 50-credits_package[2][2], 50-credits_package[2][3]-credits_package[2][2]],
                        ["l1", 50-credits_package[3][2], 50-credits_package[3][3]-credits_package[3][2]]]

    for level in endorsement_data:
        if level[1] < 0:
            level[1] = 0
        if level[2] < 0:
            level[2] = 0

    # LIT, NUM, ...
    cur.execute(get_all_lit_num_things, (session['user_id'],))
    lit_num_data = cur.fetchall()

    curriculum_stuff = [get_categories(lit_num_data, 1), get_categories(lit_num_data, 2), get_categories(lit_num_data, 3), get_categories(lit_num_data, 4)]

    return render_template("overview.html",
                           standards=standards, results=credits_package, endorsement=endorsement_data,
                           litnum=curriculum_stuff, logged_in=is_logged_in(), session=session)


@app.route('/new-achievement')
def load_add_credits(message=False, colour="light"):
    if not is_logged_in():
        return login_page(not_logged_in, "primary")

    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    standards_exist = cur.execute(count_rows_standard_user, (session['user_id'],)).fetchall()[0][0] > 0

    if standards_exist:
        cur.execute(get_all_standard_names, (session['user_id'],))
        asnumbers = cur.fetchall()
        return render_template("enter_credits.html", as_numbers=asnumbers, alert=message,
                               logged_in=is_logged_in(), session=session, colour=colour)
    else:
        print("ERROR: User has no standards; redirected towards enter standards page.")
        return load_add_standard(data_missing, "danger")


@app.route('/add-credits', methods=['POST'])
def add_credits():
    if not is_logged_in():
        return login_page(not_logged_in, "primary")

    entry_name = request.form['input_as']
    entry_grade = request.form['input_grade']
    user_id = session['user_id']

    print("USER INPUT: {}, {}, {}".format(entry_name, entry_grade, user_id))

    # Check if input valid.
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    cur.execute(count_rows_credit_entry, (entry_name, user_id,))

    result_standard = cur.fetchall()
    result_standard = result_standard[0][0]

    cur.execute(count_rows_new_entry, (entry_name, user_id))
    result_results = cur.fetchall()
    result_results = result_results[0][0]

    if result_standard < 1:
        print("ERROR: Some error with the standards on the tables.")
        return load_add_credits(data_used, "alert")

    elif result_results >= 1:
        print("USER: Standard already entered.")
        return load_add_credits(data_used, "warning")

    else:
        con = create_connection(DATABASE_NAME)
        entry_data = (entry_name, entry_grade, user_id)

        cur = con.cursor()
        cur.execute(new_credit_entry_query, entry_data)

        con.commit()
        con.close()
        return load_add_credits(success, "success")


@app.route('/new-standard')
def load_add_standard(message=False, colour="light"):
    if not is_logged_in():
        return login_page(not_logged_in, "primary")
    else:
        return render_template("enter_standard.html", alert=message, logged_in=is_logged_in(), session=session, colour=colour)


@app.route('/add-standard', methods=['POST'])
def add_standard():
    if not is_logged_in():
        return login_page(not_logged_in, "primary")

    entry_as = request.form['standard_name']
    entry_desc = request.form['description']
    entry_cred = request.form['credits']
    entry_lev = request.form['ncea_level']
    entry_read = request.form['reading']
    entry_writ = request.form['writing']
    entry_lit = request.form['literacy']
    entry_num = request.form['numeracy']
    entry_ue = request.form['ue_credits']
    user_id = session['user_id']

    print("USER INPUT: {}, {}, {}, {}, {}, {}, {}, {}, {}, {}".format
          (entry_as, entry_desc, entry_cred, entry_lev, entry_read, entry_writ, entry_lit, entry_num, entry_ue, user_id))

    # Check if input valid:
    # Check if credit number above / equal to 0, if int.
    try:
        if 0 > int(entry_cred):
            return load_add_standard(credit_value, "warning")
    except TypeError or ValueError:
        print("ERROR: Integer input (credit number) is not written in integers.")
        return load_add_standard(int_input, "warning")

    # Check if AS number too large / too small, if int.
    try:
        if int(entry_as) <= 0 or 2147483647 < int(entry_as):
            return load_add_standard(as_value, "warning")

    except TypeError or ValueError:
        print("ERROR: Integer input (AS number) is not written in integers.")
        return load_add_standard(int_input, "warning")

    # Check if the AS number already exists
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    cur.execute(count_rows_credit_entry, (entry_as, user_id, ))
    result_standard = cur.fetchall()
    result_standard = result_standard[0][0]
    if result_standard > 0:
        print("ERROR: AS Number exists already.")
        return load_add_standard(as_input, "warning")

    else:
        # Creates standard
        con = create_connection(DATABASE_NAME)
        entry_data = (entry_as, entry_desc, entry_cred, entry_lev, entry_read, entry_writ, entry_lit, entry_num, entry_ue, user_id)
        cur = con.cursor()
        cur.execute(new_standard_entry_query, entry_data)
        con.commit()
        con.close()

        print('STATEMENT: Input added successfully.')
        return load_add_standard(success, "success")


@app.route('/register')
def register(message=False, colour="primary"):
    if is_logged_in():
        return login_page(not_logged_in, "primary")
    return render_template("register.html", error_message=message, logged_in=is_logged_in(), session=session, colour=colour)


@app.route('/create-new-user', methods=['POST'])
def create_new_user():
    username = request.form['username']
    password1 = request.form['password1']
    password2 = request.form['password2']

    if password1 != password2:
        return redirect('register/password')

    hashed_password = flask_bcrypt.generate_password_hash(password1).decode('utf-8')
    new_user = (username, hashed_password)

    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    # Catches user name already exists errors.
    try:
        cur.execute(create_user, new_user)
    except sqlite3.IntegrityError:
        return redirect('/register/username')

    con.commit()
    con.close()

    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    user_data = cur.execute(find_user, (username,)).fetchall()[0]
    print("NEW USER: {}".format(user_data))
    user_id = user_data[0]

    session['user_id'] = user_id
    session['username'] = username
    print("STATUS: ", user_id, "created and in session.")
    return redirect('/')


@app.route('/logging-in', methods=['POST'])
def login():
    username = request.form['login-username']
    password = request.form['login-password']

    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    # Check if there are multiple accounts or none of that username.
    cur.execute(count_rows_username, (username,))
    user_check = cur.fetchall()[0][0]
    print("user_check: {}".format(user_check))
    if user_check > 1:
        return login_page(account_error, "danger")
    elif user_check == 0:
        return login_page(incorrect_input, "warning")

    # Check if data exist (?)
    user_data = cur.execute(find_user, (username,)).fetchall()
    try:
        user_id = user_data[0][0]
        username = user_data[0][1]
        db_password = user_data[0][2]
    except IndexError:
        return login_page(incorrect_input, "warning")

    # Checks if password is correct.
    if not flask_bcrypt.check_password_hash(db_password, password):
        print("ERROR: Hash code doesn't align with user's input.")
        return login_page(incorrect_input, "warning")

    session['user_id'] = user_id
    session['username'] = username
    return redirect('/')


@app.route('/logout')
def logout():
    if not is_logged_in():
        return login_page(not_logged_in, "primary")

    print("Status: User logged out.")
    # print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    # print(list(session.keys()))
    return redirect('/')


@app.route('/settings')
def settings_page(message=False, colour="primary"):
    if is_logged_in():
        user_info = [session['user_id'], session['username']]
        return render_template("settings.html", user=user_info, session=session, alert=message, colour=colour)
    else:
        return render_template("register.html")


@app.route('/settings/change-password', methods=['POST'])
def change_password():
    if is_logged_in():
        # check old password
        con = create_connection(DATABASE_NAME)
        cur = con.cursor()
        user_data = cur.execute(find_user, (session['username'],)).fetchall()
        old_pw = request.form['oldpassword']

        # Check if the password was correctly entered.
        # Check if the account exist in the data base. If not, log out and notify user.
        try:
            db_password = user_data[0][2]
        except IndexError:
            print("ERROR: Index error occured during db password check. User logged out.")
            [session.pop(key) for key in list(session.keys())]
            return login_page(account_error, "danger")

        # Check if the password is correct.
        if not flask_bcrypt.check_password_hash(db_password, old_pw):
            print("Hash doesn't align with user input.")
            [session.pop(key) for key in list(session.keys())]
            return login_page(incorrect_input, "warning")

        new_pw_1 = request.form['newpassword1']
        new_pw_2 = request.form['newpassword2']

        # Check if the new password was typed correctly. If not, return and notify user.
        if new_pw_1 != new_pw_2:
            print("USER ERROR: Passwords don't align.")
            message = "The passwords aren't the same! Try again."
            colour = "warning"
            return settings_page(password_match, "warning")

        # Overwrite password.
        hashed_password = flask_bcrypt.generate_password_hash(new_pw_1).decode('utf-8')
        user_id = session['user_id']
        user_data = (hashed_password, user_id)

        cur.execute(setting_change_password, user_data)
        return settings_page(success, "success")

    else:
        return login_page(not_logged_in, "primary")


if __name__ == "__main__":
    app.run(host='0.0.0.0')
