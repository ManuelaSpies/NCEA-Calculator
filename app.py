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


def login_check():
    if is_logged_in() == False:
        return login_page(not_logged_in, "primary")
    else:
        return True


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

    con.commit()
    con.close()

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


def check_password(user_input, user_session=session):
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    user_data = cur.execute(find_user, (user_session['username'],)).fetchall()
    con.commit()
    con.close()

    # Check if the account exist in the data base. If not, log out and notify user.
    try:
        db_password = user_data[0][2]
    except IndexError:
        print("ERROR: Index error occured during db password check. User logged out.")
        [user_session.pop(key) for key in list(user_session.keys())]
        return [False, account_error, "danger"]
        # return render_template("Login.html", message=account_error, colour="danger")

    # Check if the password is correct.
    if not flask_bcrypt.check_password_hash(db_password, user_input):
        print("ERROR: Hash doesn't align with user input. User logged out.")
        [user_session.pop(key) for key in list(user_session.keys())]
        return [False, incorrect_input, "warning"]
        # return render_template("Login.html", message=False, colour="light")

    return [True, False, "light"]


@app.route('/')
def main():
    if is_logged_in() == False:
        return redirect('/login')

    # Credit's Package: [[all [name, total, e, m, a, left, codename (all/l3/...)], l3, l2, l1]
    credits_package = credits_numbers()

    return render_template("home.html", results=credits_package, logged_in=is_logged_in(), session=session)


@app.route('/login')
def login_page(message=False, colour="light"):
    if is_logged_in() is False:
        return render_template("login.html", message=message, colour=colour)
    else:
        return redirect('/')


@app.route('/contact')
def contact():
    if is_logged_in() != False:
        base = "base.html"
    else:
        base = "nologin_base.html"
    return render_template("contact.html", session=session, base=base)


@app.route('/gallery')
def gallery():
    if is_logged_in() != False:
        base = "base.html"
    else:
        base = "nologin_base.html"
    return render_template("gallery.html", session=session, base=base)


@app.route('/overview')
def overview():
    if is_logged_in() == False:
        return redirect('/login')

    # LIST OF ALL COMPLETED STANDARDS
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    cur.execute(get_all_done_standards, (session['user_id'],))
    standards = cur.fetchall()

    con.commit()
    con.close()

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
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    cur.execute(get_all_lit_num_things, (session['user_id'],))
    lit_num_data = cur.fetchall()

    con.commit()
    con.close()

    curriculum_stuff = [get_categories(lit_num_data, 1), get_categories(lit_num_data, 2), get_categories(lit_num_data, 3), get_categories(lit_num_data, 4)]

    return render_template("overview.html",
                           standards=standards, results=credits_package, endorsement=endorsement_data,
                           litnum=curriculum_stuff, logged_in=is_logged_in(), session=session)


@app.route('/new-achievement')
def load_add_credits(message=False, colour="light"):
    login_check()

    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    standards_exist = cur.execute(count_rows_standard_user, (session['user_id'],)).fetchall()[0][0] > 0

    con.commit()
    con.close()

    if standards_exist:
        con = create_connection(DATABASE_NAME)
        cur = con.cursor()

        cur.execute(get_all_standard_names, (session['user_id'],))
        asnumbers = cur.fetchall()

        con.commit()
        con.close()
        return render_template("enter_credits.html", as_numbers=asnumbers, alert=message,
                               logged_in=is_logged_in(), session=session, colour=colour)
    else:
        print("ERROR: User has no standards; redirected towards enter standards page.")
        return load_add_standard(data_missing, "danger")


@app.route('/add-credits', methods=['POST'])
def add_credits(information=[]):
    login_check()
    user_id = session['user_id']

    if information == []:
        entry_name = request.form['input_as']
        entry_grade = request.form['input_grade']
    else:
        entry_name = information[0]
        entry_grade = information[1]

    print("USER INPUT: {}, {}, {}".format(entry_name, entry_grade, user_id))

    # Check if input valid.
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    cur.execute(count_rows_credit_entry, (entry_name, user_id,))
    result_standard = cur.fetchall()
    result_standard = result_standard[0][0]

    con.commit()
    con.close()
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    cur.execute(count_rows_new_entry, (entry_name, user_id))
    result_results = cur.fetchall()
    result_results = result_results[0][0]

    con.commit()
    con.close()

    print("yay")

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
    login_check()
    action = "/add-standard"
    return render_template("enter_standard.html", alert=message, logged_in=is_logged_in(),
                           session=session, colour=colour, content=[], action=action)


@app.route('/add-standard', methods=['POST'])
def add_standard():
    login_check()

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

    con.commit()
    con.close()

    result_standard = result_standard[0][0]
    if result_standard > 0:
        print("ERROR: AS Number exists already.")
        return load_add_standard(as_input, "warning")

    else:
        # Creates standard
        entry_data = (entry_as, entry_desc, entry_cred, entry_lev, entry_read, entry_writ, entry_lit, entry_num, entry_ue, user_id)

        con = create_connection(DATABASE_NAME)
        cur = con.cursor()

        cur.execute(new_standard_entry_query, entry_data)

        con.commit()
        con.close()
        print('STATEMENT: Standard added successfully.')

        # Grade work
        grade = request.form['input_grade']
        if grade != "NA":
            add_credits([entry_as, grade])
            print("STATUS: Added grade {} for {} of user {} (ID: {}).".format(entry_as, grade, session['username'], user_id))

        return load_add_standard(success, "success")


@app.route('/delete-standard/<standard_id>')
def delete_standard(standard_id):
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    cur.execute(delete_standard_query, standard_id)

    con.commit()
    con.close()

    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    cur.execute(delete_result_query, standard_id)

    con.commit()
    con.close()

    print('STATEMENT: Standard {} was deleted by {} (ID: {}).'.format(standard_id, session['username'], session['user_id']))
    return redirect('/overview')


@app.route('/edit-standard/<standard_id>')
def edit_standard(standard_id):
    login_check()
    action = "/update-standard".format(standard_id)

    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    error = False
    try:
        old_version = cur.execute(get_standard_query, (standard_id, session['user_id'],)).fetchall()
    except IndexError:
        message = unknown_url
        colour = "warning"
        content = [[], [], [], [], [], [], [], [], [], [], [], []]
        error = True
        old_version = "error"

    con.commit()
    con.close()

    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    grade_get = True
    try:
        standard_name = old_version[0][1]
    except IndexError:
        grade_get = False
        grade = "NA"

    if grade_get == True:
        try:
            grade = cur.execute(get_grade_query, (standard_name, session['user_id'],)).fetchall()[0][0]
        except IndexError:
            grade = "NA"

    con.commit()
    con.close()

    if error is True and len(old_version) > 1:
        return load_add_standard(data_problem, "danger")

    elif error is False:
        message = False
        colour = "primary"
        content = old_version[0]
        content = content + (grade,)

    print(content)
    return render_template("enter_standard.html", alert=message, logged_in=is_logged_in(),
                           session=session, colour=colour, content=content, action=action)


@app.route('/update-standard', methods=['POST'])
def update_standard():
    login_check()

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

    con.commit()
    con.close()

    result_standard = result_standard[0][0]
    if result_standard > 0:
        print("ERROR: AS Number exists already.")
        return load_add_standard(as_input, "warning")

    else:
        # Updates standard
        entry_data = (entry_as, entry_desc, entry_cred, entry_lev, entry_read, entry_writ, entry_lit)

    return "uwu"


@app.route('/register')
def register(message=False, colour="primary"):
    if is_logged_in() is not False:
        return redirect('/')
    return render_template("register.html", error_message=message, logged_in=is_logged_in(), session=session, colour=colour)


@app.route('/create-new-user', methods=['POST'])
def create_new_user():
    username = request.form['username']
    password1 = request.form['password1']
    password2 = request.form['password2']

    if password1 != password2:
        return register(password_match, 'warning')

    hashed_password = flask_bcrypt.generate_password_hash(password1).decode('utf-8')
    new_user = (username, hashed_password)

    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    # Catches user name already exists errors.
    try:
        cur.execute(create_user, new_user)
    except sqlite3.IntegrityError:
        return register(username_exists, 'warning')

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

    con.commit()
    con.close()

    if user_check > 1:
        return login_page(account_error, "danger")
    elif user_check == 0:
        return login_page(incorrect_input, "warning")

    # Check if data exist (?)
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    user_data = cur.execute(find_user, (username,)).fetchall()

    con.commit()
    con.close()

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
    login_check()
    print("Status: User logged out.")
    # print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    # print(list(session.keys()))
    return redirect('/')


@app.route('/settings')
def settings_page(message=False, colour="primary"):
    login_check()

    user_info = [session['user_id'], session['username']]
    return render_template("settings.html", user=user_info, session=session, alert=message, colour=colour)


@app.route('/change-username', methods=['POST'])
def change_username():
    # Checks if the user is logged in
    login_check()

    # Is the password correct?
    password = request.form['password']
    pw_check = check_password(password, session)
    if pw_check[0] is False:
        return render_template("login.html", message=pw_check[1], colour=pw_check[2])

    # Tries to enter the new user name --> catches error if username exists
    username = request.form['newusername']
    user_data = (username, session['user_id'])

    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    try:
        cur.execute(setting_change_username, user_data)
    except sqlite3.IntegrityError:
        print("USER ERROR: The username already exists.")
        return settings_page(username_exists, 'warning')
    con.commit()
    con.close()

    # Overwrites session
    session['username'] = username

    return settings_page(success, 'success')


@app.route('/change-password', methods=['POST'])
def change_password():
    login_check()

    # check old password
    old_pw = request.form['oldpassword']
    pw_check = check_password(old_pw, session)
    if pw_check[0] is False:
        return render_template("login.html", message=pw_check[1], colour=pw_check[2])

    # Check if the new password was typed correctly. If not, return and notify user.
    new_pw_1 = request.form['newpassword1']
    new_pw_2 = request.form['newpassword2']
    if new_pw_1 != new_pw_2:
        print("USER ERROR: Passwords don't align.")
        return settings_page(password_match, "warning")

    # Overwrite password.
    hashed_password = flask_bcrypt.generate_password_hash(new_pw_1).decode('utf-8')
    user_id = session['user_id']
    user_data = (hashed_password, user_id)
    print("User data: ", user_data)

    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    cur.execute(setting_change_password, user_data)
    con.commit()
    con.close()

    return settings_page(success, "success")


@app.route('/delete-account', methods=['GET', 'POST'])
def delete_user_account():
    # Check if the user agrees to delete the account
    security = request.form['security'].lower().replace(" ", "")
    if security != 'yes':
        print("ACTION ABORTED: User did not agree.")
        return settings_page(agreement, "warning")

    # Username check
    username = request.form['username']
    if username != session['username']:
        print("ACTION ABORTED: User did not input username correctly.")
        return settings_page(incorrect_input, "warning")

    # Password check 1
    password1 = request.form['password1']
    pw_check1 = check_password(password1, session)
    if pw_check1[0] is False:
        print("ACTION ABORTED: User did not input password (input one) correctly.")
        return render_template("login.html", message=pw_check1[1], colour=pw_check1[2])

    # Password check 2
    password2 = request.form['password2']
    pw_check2 = check_password(password2, session)
    if pw_check2[0] is False:
        print("ACTION ABORTED: User did not input password (input two) correctly.")
        return render_template("login.html", message=pw_check2[1], colour=pw_check2[2])

    # Deleting the account process
    user_id = session['user_id']

    # Deleting data from standard table
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    cur.execute(delete_account_standard, (user_id,))
    con.commit()
    con.close()

    # Deleting data from result table
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    cur.execute(delete_account_result, (user_id,))
    con.commit()
    con.close()

    # Deleting data from user table
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    cur.execute(delete_account_user, (user_id,))
    con.commit()
    con.close()

    print("STATUS: Deleted user {} (ID: {}). Logged out.".format(username, user_id))
    return redirect('/logout')


@app.route('/delete-data', methods=['GET', 'POST'])
def delete_user_data():
    # Check if the user agrees to delete all data
    security = request.form['security2'].lower().replace(" ", "")
    if security != 'yes':
        print("ACTION ABORTED: User did not agree.")
        return settings_page(agreement, "warning")

    # Password check 1
    password1 = request.form['pw_data']
    pw_check1 = check_password(password1, session)
    if pw_check1[0] is False:
        print("ACTION ABORTED: User did not input password (input one) correctly.")
        return render_template("login.html", message=pw_check1[1], colour=pw_check1[2])

    # Deleting the account process
    user_id = session['user_id']

    # Deleting data from standard table
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    cur.execute(delete_account_standard, (user_id,))
    con.commit()
    con.close()

    # Deleting data from result table
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    cur.execute(delete_account_result, (user_id,))
    con.commit()
    con.close()

    print("STATUS: All data of {} (ID: {}) was deleted.".format(session['username'], session['user_id']))
    return settings_page(success, 'success')


@app.route('/loop')
def loop_usage_thing():
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    data = cur.execute(select_all).fetchall()
    con.commit()
    con.close()

    list_of_standards = [['Standard Name:', ], ['Description:', ], ['Credits:', ], ['NCEA Level: ',]]

    for item in data:
        list_of_standards[0].append(item[0])
        list_of_standards[1].append(item[1])
        list_of_standards[2].append(item[2])
        list_of_standards[3].append(item[3])
    print(list_of_standards)
    return render_template("all_standards.html", the_list=list_of_standards)


if __name__ == "__main__":
    app.run(host='0.0.0.0')
