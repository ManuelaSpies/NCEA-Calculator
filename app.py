# Importing modules, ...
from flask import Flask, render_template, request, redirect, session
import sqlite3
from sqlite3 import Error
from import_data import *
from import_messages import *
from flask_bcrypt import Bcrypt

# constants & app-wide variables
DATABASE_NAME = "credit.db"
app = Flask(__name__)
flask_bcrypt = Bcrypt(app)
app.secret_key = "コレは秘密다. Jingle bells Käsekuchen. 4729371927"


def is_logged_in():
    """this function checks if the user is logged in or not, and returns a True/False depending on that"""
    try:
        print("Session:", session['username'])
        return session['user_id'] != ""
    except KeyError:
        print("Not logged in")
        return False


def login_check():
    """this function checks if a user is logged in. If not, the function redirects them to the login page"""
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

    # Count the amount of credits by grade.
    for standard in entries:
        if standard[1] == "E":
            e_total += standard[0]
        elif standard[1] == "M":
            m_total += standard[0]
        elif standard[1] == "A":
            a_total += standard[0]

    # Sets the amount of credits left to achieve level to 80 (if Level 1), 60 (Level 2 & 3) or zero (if it's a total)
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

    return [name, total, e_total, m_total, a_total, left]


def credits_numbers():
    """collects the credits from all grades and puts them together in one package"""
    all_credits = get_credits("All", get_credits_all_query)
    l3_credits = get_credits("Level 3", get_credits_l3_query)
    l2_credits = get_credits("Level 2", get_credits_12_query)
    l1_credits = get_credits("Level 1", get_credits_l1_query)

    # Adds the category of credits
    all_credits.append('all')
    l3_credits.append('l3')
    l2_credits.append('l2')
    l1_credits.append('l1')

    return [all_credits, l3_credits, l2_credits, l1_credits]


def get_categories(data, number):
    """counts values in a list that have a 'Yes' attached"""
    outcome = 0
    for standard in data:
        if standard[number] == "Yes":
            outcome += standard[0]

    return outcome


def check_password(user_input, user_session=session):
    """compares user-input password with database hash and returns adequate response."""
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
    """renders home.html, if the user is logged in"""
    if is_logged_in() == False:
        return redirect('/login')

    # Credit's Package: [[all [name, total, e, m, a, left, codename (all/l3/...)], l3, l2, l1]
    credits_package = credits_numbers()

    return render_template("home.html", results=credits_package, logged_in=is_logged_in(), session=session)


@app.route('/login')
def login_page(message=False, colour="light"):
    """renders login page, unless the user is logged in"""
    if is_logged_in() is False:
        return render_template("login.html", message=message, colour=colour)
    else:
        return redirect('/')


@app.route('/contact')
def contact():
    """renders contact page, with correct base template"""
    if is_logged_in() != False:
        base = "base.html"
    else:
        base = "nologin_base.html"
    return render_template("contact.html", session=session, base=base)


@app.route('/gallery')
def gallery():
    """renders gallery page, with correct base template"""
    if is_logged_in() != False:
        base = "base.html"
    else:
        base = "nologin_base.html"
    return render_template("gallery.html", session=session, base=base)


@app.route('/overview')
def overview(message=False, colour="light"):
    """renders overview including data displayed"""
    if is_logged_in() == False:
        return redirect('/login')

    # fetches list of all completed credits
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    cur.execute(get_all_done_standards, (session['user_id'],))
    standards = cur.fetchall()
    con.commit()

    # Stores all credit information in credits_package
    credits_package = credits_numbers()

    # Creates list holding the endorsement information
    endorsement_data = [["l3", 50 - credits_package[1][2], 50 - credits_package[1][3] - credits_package[1][2]],
                        ["l2", 50 - credits_package[2][2], 50 - credits_package[2][3] - credits_package[2][2]],
                        ["l1", 50 - credits_package[3][2], 50 - credits_package[3][3] - credits_package[3][2]]]

    for level in endorsement_data:
        if level[1] < 0:
            level[1] = 0
        if level[2] < 0:
            level[2] = 0

    # Fetches and stores all information regarding literacy, numeracy, UE etc. (All Yes/No ones).
    cur = con.cursor()
    cur.execute(get_all_lit_num_things, (session['user_id'],))
    lit_num_data = cur.fetchall()
    con.commit()
    con.close()

    curriculum_stuff = [get_categories(lit_num_data, 1), get_categories(lit_num_data, 2),
                        get_categories(lit_num_data, 3), get_categories(lit_num_data, 4)]

    return render_template("overview.html",
                           standards=standards, results=credits_package, endorsement=endorsement_data,
                           litnum=curriculum_stuff, logged_in=is_logged_in(), session=session,
                           message=message, colour=colour)


@app.route('/new-achievement')
def load_add_credits(message=False, colour="light"):
    """renders page to enter a grade, if there are standards"""
    login_check()

    # Checks if there are any standards for the user
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    standards_exist = cur.execute(count_rows_standard_user, (session['user_id'],)).fetchall()[0][0] > 0
    con.commit()

    # If the user has standards, fetches all standards and renders page, or redirects to the page to /add-standard
    if standards_exist:
        cur = con.cursor()
        cur.execute(get_all_standard_names, (session['user_id'],))
        asnumbers = cur.fetchall()
        con.commit()
        con.close()
        return render_template("enter_credits.html", as_numbers=asnumbers, alert=message,
                               logged_in=is_logged_in(), session=session, colour=colour)
    else:
        con.close()
        return load_add_standard(data_missing, "danger")


@app.route('/add-credits', methods=['POST'])
def add_credits(information=[]):
    """adds result, stored in information, to the database"""
    login_check()
    user_id = session['user_id']

    # determines if the input comes from a form or was passed on, and stores data according to that
    if information == []:
        entry_name = request.form['input_as']
        entry_grade = request.form['input_grade']

    else:
        entry_name = information[0]
        entry_grade = information[1]
        entry_id = information[2]

    # Checks if the standard (AS number) exists
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    cur.execute(count_rows_credit_entry, (entry_name[0][0], user_id))
    result_standard = cur.fetchall()
    result_standard = result_standard[0][0]
    con.commit()

    # Checks if there already is a result
    cur = con.cursor()
    cur.execute(count_rows_new_entry, (entry_name[0][0], user_id))
    result_results = cur.fetchall()
    result_results = result_results[0][0]
    con.commit()

    # Error & appropriate redirect if the standard doesn't exist.
    if result_standard <= 0:
        print("USER ERROR: No such standard exists.")
        con.close()
        return load_add_credits(data_used, "alert")

    # Error & appropriate redirect if there is a result.
    elif result_results >= 1:
        print("USER ERROR: Standard grade already entered.")
        con.close()
        return load_add_credits(data_used, "warning")

    # Adds result to database
    else:
        entry_data = (entry_name, entry_grade, user_id)
        cur = con.cursor()
        cur.execute(new_credit_entry_query, entry_data)
        con.commit()
        con.close()

        return load_add_credits(success, "success")


@app.route('/new-standard')
def load_add_standard(message=False, colour="light"):
    """renders page to add a new standard"""
    login_check()
    action = "/add-standard"

    return render_template("enter_standard.html", alert=message, logged_in=is_logged_in(),
                           session=session, colour=colour, content=[], action=action)


@app.route('/add-standard', methods=['POST'])
def do_add_standard():
    """adds a new standard, or redirects with appropriate error"""
    login_check()

    # stores data from the form
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

    # Checks if credit number above or equal to 0 and if it's an integer, or raises appropriate error
    try:
        if 0 > int(entry_cred):
            print("USER ERROR: AS Number not above or equal to zero.")
            return load_add_standard(credit_value, "warning")
    except TypeError or ValueError:
        print("USER ERROR: AS Number not written as integer.")
        return load_add_standard(int_input, "warning")

    # Checks if AS number too large or too small and if it's an integer, or raises appropriate error.
    try:
        if int(entry_as) <= 0 or 2147483647 < int(entry_as):
            print("USER ERROR: AS Number outside boundaries.")
            return load_add_standard(as_value, "warning")
    except TypeError or ValueError:
        print("ERROR: AS number not written as integer.")
        return load_add_standard(int_input, "warning")

    # Checks if the AS number already exists
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    cur.execute(count_rows_credit_entry, (entry_as, user_id,))
    result_standard = cur.fetchall()
    result_standard = result_standard[0][0]
    con.commit()

    # Checks if the standard number is already used by the user.
    if result_standard >= 1:
        print("USER ERROR: AS Number exists already.")
        con.close()
        return load_add_standard(as_input, "warning")

    else:
        # adds standard to database
        entry_data = (
            entry_as, entry_desc, entry_cred, entry_lev, entry_read, entry_writ, entry_lit, entry_num, entry_ue,
            user_id)
        cur = con.cursor()
        cur.execute(new_standard_entry_query, entry_data)
        con.commit()

        # gets grade & checks if it's not NA
        grade = request.form['input_grade']

        if grade != "NA":
            # fetches standard database ID from database
            cur = con.cursor()
            entry_id = cur.execute(get_standard_id, (entry_as, user_id,)).fetchall()[0][0]
            con.commit()

            # adds grade
            add_credits([entry_as, grade, entry_id])

        con.close()
        return load_add_standard(success, "success")                              
                                                                                  
                                                                                  
@app.route('/delete-standard/<standard_id>')                                      
def delete_standard(standard_id):
    """deletes standard with the given standard id"""
    con = create_connection(DATABASE_NAME)

    # deletes standard from standard table
    cur = con.cursor()
    cur.execute(delete_standard_query, standard_id)
    con.commit()

    # deletes grade from result table
    cur = con.cursor()
    cur.execute(delete_result_query, standard_id)
    con.commit()
    con.close()

    return redirect('/overview')


@app.route('/edit-standard/<standard_id>')
def edit_standard(standard_id):
    """renders form to edit a standard, including data to be entered"""
    login_check()
    action = "/update-standard/{}".format(standard_id)

    # checks if the standard exists. If not, fills in an empty list for the form
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    error = False
    try:
        old_version = cur.execute(get_standard_query, (standard_id, session['user_id'],)).fetchall()
    except IndexError:
        message = unknown_url
        colour = "warning"
        error = True
        content = [[], [], [], [], [], [], [], [], [], [], [], []]
        old_version = "error"
    con.commit()

    cur = con.cursor()
    # Determine whenever the standard has a grade attached
    # grade_get = True
    # try:
    #     standard_name = old_version[0][1]
    # except IndexError:
    #     grade_get = False
    #     grade = "NA"

    # finds grade from database, if existent, or saves it as NA
    try:
        grade = cur.execute(get_grade_query, (standard_id, session['user_id'],)).fetchall()[0][0]
        con.commit()
    except IndexError:
        grade = "NA"
    con.close()

    # If the standard exists, prepares information for the form
    if error is False:
        message = False
        colour = "primary"
        content = old_version[0]
        content = content + (grade,)

    return render_template("enter_standard.html", alert=message, logged_in=is_logged_in(),
                           session=session, colour=colour, content=content, action=action)


@app.route('/update-standard/<standard_id>', methods=['POST'])
def update_standard(standard_id):
    """Checks validity of data from form and updates standard or raises appropriate error"""

    login_check()

    # stores data from form in variables
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

    # Check if credit number above or equal to 0 and if it's an integer, or raises appropriate error message
    try:
        if 0 > int(entry_cred):
            return load_add_standard(credit_value, "warning")
    except TypeError or ValueError:
        print("ERROR: Integer input (credit number) is not written in integers.")
        return load_add_standard(int_input, "warning")

    # Check if AS number too large or too small and if it's an integer, or raises appropriate error message
    try:
        if int(entry_as) <= 0 or 2147483647 < int(entry_as):
            return load_add_standard(as_value, "warning")
    except TypeError or ValueError:
        print("ERROR: Integer input (AS number) is not written in integers.")
        return load_add_standard(int_input, "warning")

    # Check if the AS number was changed
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    previous_as = cur.execute(get_standard_query, (standard_id, user_id)).fetchall()[0][1]
    con.commit()

    if int(previous_as) != int(entry_as):
        # fetches number of standards with the new AS number & raises error if it exists
        cur = con.cursor()
        cur.execute(count_rows_credit_entry, (entry_as, user_id,))
        result_standard = cur.fetchall()
        con.commit()
        result_standard = result_standard[0][0]

        if result_standard >= 1:
            print("ERROR: AS Number already in usage.")
            return load_add_standard(as_input, "warning")

    # Updates standard in database
    entry_data = (entry_as, entry_desc, entry_cred, entry_lev, entry_read, entry_writ, entry_lit, entry_num,
                  entry_ue, standard_id, user_id)
    cur = con.cursor()
    cur.execute(update_standard_query, entry_data)
    con.commit()

    # Debugging: checking if the new standard in the DB is correctly entered
    cur = con.cursor()
    new_standard = cur.execute(get_standard_query, (standard_id, user_id)).fetchall()[0]
    con.commit()
    print("Entry data into db: ",  entry_data)
    print("New data in db: ", new_standard)

    # If the grade is NA, then the form is complete and the user is given the overview.
    grade = request.form['input_grade']
    if grade == "NA":
        return redirect('/overview')

    # Checks if there already is a result.
    cur = con.cursor()
    row_count = cur.execute(count_rows_new_entry, (standard_id, user_id)).fetchall()[0][0]
    con.commit()

    if row_count == 0:
        # Adds grade to db & redirects to overview
        cur = con.cursor()
        cur.execute(new_credit_entry_query, (standard_id, grade, user_id))
        con.commit()
        con.close()
        return redirect('/overview')

    elif row_count == 1:
        # Update grade in the database & redirects to overview
        cur = con.cursor()
        cur.execute(update_grade_query, (grade, standard_id, user_id))
        con.commit()
        con.close()
        return redirect('/overview')

    else:
        # Raises error
        con.close()
        print("ERROR: There is more than one result with the same standard ID in the result table!")
        return overview(result_multiple, "danger")


@app.route('/register')
def register(message=False, colour="primary"):
    """renders register page"""
    if is_logged_in() is not False:
        return redirect('/')
    return render_template("register.html", error_message=message, logged_in=is_logged_in(), session=session,
                           colour=colour)


@app.route('/create-new-user', methods=['POST'])
def create_new_user():
    """creates new user with encrypted password, after validating username and password"""
    # stores data from form in variables
    username = request.form['username']
    password1 = request.form['password1']
    password2 = request.form['password2']

    # checks if the two passwords are the same, and rises appropriate error if not
    if password1 != password2:
        return register(password_match, 'warning')

    # hashes password & prepares adding the user to the database
    hashed_password = flask_bcrypt.generate_password_hash(password1).decode('utf-8')
    new_user = (username, hashed_password)

    # adds new user to the database
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    # Try/except catches user name already exists-error
    try:
        cur.execute(create_user, new_user)
    except sqlite3.IntegrityError:
        return register(username_exists, 'warning')
    con.commit()

    # fetches user_id & updates session
    cur = con.cursor()
    user_data = cur.execute(find_user, (username,)).fetchall()[0]
    user_id = user_data[0]

    session['user_id'] = user_id
    session['username'] = username

    return redirect('/')


@app.route('/logging-in', methods=['POST'])
def login():
    """logs user in, or raises errors if appropriate"""
    # stores user input
    username = request.form['login-username']
    password = request.form['login-password']

    # Checks if there is an account with the username.
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    cur.execute(count_rows_username, (username,))
    user_check = cur.fetchall()[0][0]
    con.commit()

    if user_check > 1:
        print("ERROR: There is more than one account with the same username.")
        return login_page(account_error, "danger")
    elif user_check == 0:
        print("USER ERROR: This username does not exist.")
        return login_page(incorrect_input, "warning")

    # Fetches information on the username or raises error (concerning something being wrong with database)
    cur = con.cursor()
    user_data = cur.execute(find_user, (username,)).fetchall()
    con.commit()
    con.close()

    try:
        user_id = user_data[0][0]
        username = user_data[0][1]
        db_password = user_data[0][2]
    except IndexError:
        print("ERROR: Something is wrong with the data received from the database.")
        return login_page(incorrect_input, "warning")

    # Checks if password is correct.
    if not flask_bcrypt.check_password_hash(db_password, password):
        print("USER ERROR: Hash code doesn't align with user's input.")
        return login_page(incorrect_input, "warning")

    # Updates session and therefore logs user in
    session['user_id'] = user_id
    session['username'] = username
    return redirect('/')


@app.route('/logout')
def logout():
    """logs user out"""
    login_check()
    print("Status: User logged out.")
    # print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    # print(list(session.keys()))

    return redirect('/')


@app.route('/settings')
def settings_page(message=False, colour="primary"):
    """renders settings page with neccessary information from the session"""
    login_check()

    user_info = [session['user_id'], session['username']]
    return render_template("settings.html", user=user_info, session=session, alert=message, colour=colour)


@app.route('/change-username', methods=['POST'])
def change_username():
    """changes username after validating user input"""
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
    """changes password if input is valid"""
    login_check()

    # Checks old password
    old_pw = request.form['oldpassword']
    pw_check = check_password(old_pw, session)
    if pw_check[0] is False:
        return render_template("login.html", message=pw_check[1], colour=pw_check[2])

    # Checks if the new password was typed correctly. If not, return and notify user.
    new_pw_1 = request.form['newpassword1']
    new_pw_2 = request.form['newpassword2']
    if new_pw_1 != new_pw_2:
        print("USER ERROR: Passwords don't align.")
        return settings_page(password_match, "warning")

    # Overwrites password.
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
    """deletes account after validating user input"""
    user_id = session['user_id']

    # Check if the user agrees to delete the account
    security = request.form['security'].lower().replace(" ", "")
    if security != 'yes':
        print("ACTION ABORTED: User did not agree to deleting account.")
        return settings_page(agreement, "warning")

    # Checks if username is correctly input
    username = request.form['username']
    if username != session['username']:
        print("ACTION ABORTED: User did not input username correctly.")
        return settings_page(incorrect_input, "warning")

    # Checks if password 1 was correctly entered
    password1 = request.form['password1']
    pw_check1 = check_password(password1, session)
    if pw_check1[0] is False:
        print("ACTION ABORTED: User did not input password (input one) correctly.")
        return render_template("login.html", message=pw_check1[1], colour=pw_check1[2])

    # Checks if password 2 was correctly entered
    password2 = request.form['password2']
    pw_check2 = check_password(password2, session)
    if pw_check2[0] is False:
        print("ACTION ABORTED: User did not input password (input two) correctly.")
        return render_template("login.html", message=pw_check2[1], colour=pw_check2[2])

    # Deleting data from standard table
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    cur.execute(delete_account_standard, (user_id,))
    con.commit()

    # Deleting data from result table
    cur = con.cursor()
    cur.execute(delete_account_result, (user_id,))
    con.commit()

    # Deleting data from user table
    cur = con.cursor()
    cur.execute(delete_account_user, (user_id,))
    con.commit()
    con.close()

    return redirect('/logout')


@app.route('/delete-data', methods=['GET', 'POST'])
def delete_user_data():
    """deletes all standards and results of the user"""
    user_id = session['user_id']

    # Check if the user agrees to delete all data
    security = request.form['security2'].lower().replace(" ", "")
    if security != 'yes':
        print("ACTION ABORTED: User did not agree to deleting all data.")
        return settings_page(agreement, "warning")

    # Checks if password is correctly entered
    password1 = request.form['pw_data']
    pw_check1 = check_password(password1, session)
    if pw_check1[0] is False:
        print("ACTION ABORTED: User did not input password (input one) correctly.")
        return render_template("login.html", message=pw_check1[1], colour=pw_check1[2])

    # Deleting data from standard table
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    cur.execute(delete_account_standard, (user_id,))
    con.commit()

    # Deleting data from result table
    cur = con.cursor()
    cur.execute(delete_account_result, (user_id,))
    con.commit()
    con.close()

    return settings_page(success, 'success')


if __name__ == "__main__":
    app.run(host='0.0.0.0')
