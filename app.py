#import streamlit as st
#import psycopg2
#import pandas as pd
#from db_connection import get_connection  # your connection file

#st.set_page_config(page_title="SEO Blog Manager", layout="wide")

#pip install pyotp qrcode[pil] streamlit-authenticator
import streamlit as st
import psycopg2
import pandas as pd
import pyotp   # 🔑 for Google Authenticator
import qrcode
import io
import bcrypt
from db_connection import get_connection  # your connection file
import uuid
from streamlit_option_menu import option_menu

st.set_page_config(page_title="SEO Blog Manager", layout="wide")

# ------------------- Session State ------------------- #
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "awaiting_otp" not in st.session_state:
    st.session_state["awaiting_otp"] = False
if "auth_user" not in st.session_state:
    st.session_state["auth_user"] = None
    
# ------------------- DB UTILS ------------------- #

# Helper function
def render_dynamic_list(label, key):
    for i, val in enumerate(st.session_state[key]):
        cols = st.columns([6, 1, 1])
        st.session_state[key][i] = cols[0].text_input(f"{label} {i+1}", val, key=f"{key}_{i}")
        
        # Track which row requested add/delete
        if cols[1].button("➕", key=f"{key}_add_{i}"):
            st.session_state.action["add"] = (key, i)
        if cols[2].button("🗑", key=f"{key}_del_{i}"):
            st.session_state.action["delete"] = (key, i)
                
        
def run_query(query, params=None, fetch=False, many=False):
    conn = get_connection()
    try:
        with conn:
            with conn.cursor() as cur:
                if params is not None and not isinstance(params, (list, tuple)):
                    params = (params,)  # force single value into tuple

                if many:
                    cur.executemany(query, params)
                else:
                    cur.execute(query, params)

                if fetch:
                    return cur.fetchall()
    finally:
        conn.close()


def get_user(username):
    row = run_query(
        "SELECT user_id, username, password_hash, totp_secret FROM seo.users WHERE username = %s;",
        (username,), fetch=True
    )
    if not row:
        return None

    rec = row[0]
    # If it's a dict (RealDictCursor) → use keys
    if isinstance(rec, dict):
        return rec
    # If it's a tuple → unpack manually
    else:
        user_id, uname, pwd_hash, totp_secret = rec
        return {
            "user_id": user_id,
            "username": uname,
            "password_hash": pwd_hash,
            "totp_secret": totp_secret
        }

def update_totp_secret(user_id, secret):
    run_query("UPDATE seo.users SET totp_secret = %s WHERE user_id = %s;", (secret, user_id))


def registration_page():
    st.subheader("📝 User Registration")

    new_username = st.text_input("Choose Username")
    new_password = st.text_input("Choose Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")

    if st.button("Register", key="btn_register"):
        if not new_username or not new_password:
            st.error("⚠️ Username and password required")
        elif new_password != confirm_password:
            st.error("⚠️ Passwords do not match")
        else:
            # Check if username already exists
            exists = run_query("SELECT 1 FROM seo.users WHERE username = %s;", (new_username,), fetch=True)
            if exists:
                st.error("❌ Username already exists!")
                return

            # Hash password
            hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()

            # Generate TOTP secret at registration
            secret = pyotp.random_base32()

            # Insert into DB
            run_query(
                "INSERT INTO seo.users (username, password_hash, totp_secret) VALUES (%s, %s, %s);",
                (new_username, hashed, secret)
            )

            # Generate QR for Google Authenticator
            totp = pyotp.TOTP(secret)
            uri = totp.provisioning_uri(name=new_username, issuer_name="SEO Blog Manager")
            qr = qrcode.make(uri)
            buf = io.BytesIO()
            qr.save(buf, format="PNG")

            st.success("✅ User registered successfully! Now scan the QR code below in Google Authenticator:")
            st.image(buf.getvalue())
            st.info("After scanning, you can log in with your username, password, and OTP.")


def login_page():
    #st.subheader("🔑 Login")
    st.subheader("Blog Management System - 🔑 Login")

    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")

    if st.button("Login", key="btn_login"):
        user = get_user(username)
        if not user:
            st.error("❌ Invalid username")
            return

        db_pwd = user["password_hash"]
        #st.write("DEBUG: Stored hash →", db_pwd)   # 👈 add this
        #st.write("DEBUG: Entered password →", password)  # 👈 add this

        password_ok = False

        if db_pwd:
            try:
                if bcrypt.checkpw(password.encode(), db_pwd.encode()):
                    password_ok = True
            except (ValueError, TypeError) as e:
                st.write("DEBUG: bcrypt error →", str(e))

        if not password_ok:
            st.error("❌ Invalid password")
            return

        # OTP part continues here...

        # ---- OTP Step ----
        st.session_state["awaiting_otp"] = True
        st.session_state["auth_user"] = user
        st.success("✅ Password correct. Please enter OTP.")

    if st.session_state.get("awaiting_otp"):
        otp = st.text_input("Enter 6-digit OTP", max_chars=6, key="otp_input")
        if st.button("Verify OTP", key="btn_verify_otp"):
            user = st.session_state["auth_user"]
            if not user["totp_secret"]:
                st.error("❌ No TOTP secret found. Please re-register.")
                return

            totp = pyotp.TOTP(user["totp_secret"])
            if totp.verify(otp):
                st.session_state["authenticated"] = True
                st.session_state["awaiting_otp"] = False
                st.success("🎉 Login successful!")
                st.session_state["page"] = "welcome"
                st.rerun()
                #blog_page()
            else:
                st.error("❌ Invalid OTP")
     
def logout_button():
    if st.sidebar.button("🚪 Logout"):
        st.session_state["authenticated"] = False
        st.session_state["auth_user"] = None
        st.session_state["awaiting_otp"] = False
        st.rerun()  # refresh page after logout
        
def auth_controller():
    # If user already logged in
    if st.session_state["authenticated"]:
        user = st.session_state["auth_user"]
        st.sidebar.markdown(f"👋 Hello, **{user['username']}**")
        logout_button()
        return True
    else:
        # Show login/register options
        #st.sidebar.title("User Access")
        #page = st.sidebar.radio("Select:", ["Login"])
        #page = st.sidebar.radio("Select:", ["Login", "Register"])

        if page == "Register":
            registration_page()
        else:
            login_page()

        # Stop everything until authenticated
        if not st.session_state["authenticated"]:
            st.stop()
        return True

def change_password_page():
    if not st.session_state.get("authenticated", False):
        st.error("⚠️ You must be logged in to change your password.")
        st.stop()

    user = st.session_state["auth_user"]
    st.subheader("🔑 Change Password")

    current_pw = st.text_input("Current Password", type="password", key="current_pw")
    new_pw = st.text_input("New Password", type="password", key="new_pw")
    confirm_pw = st.text_input("Confirm New Password", type="password", key="confirm_pw")

    if st.button("Update Password", key="update_pw_btn"):
        # Verify current password
        stored_hash = user["password_hash"]

        try:
            if stored_hash.startswith("$2b$"):  # bcrypt
                if not bcrypt.checkpw(current_pw.encode(), stored_hash.encode()):
                    st.error("❌ Current password is incorrect")
                    return
            else:
                if current_pw != stored_hash:
                    st.error("❌ Current password is incorrect")
                    return

        except Exception as e:
            st.error(f"⚠️ Error verifying password: {e}")
            return

        # Check new password match
        if new_pw != confirm_pw:
            st.error("❌ New passwords do not match")
            return

        if not new_pw:
            st.error("⚠️ New password cannot be empty")
            return

        # Hash new password
        new_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()

        # Update in DB
        run_query("UPDATE seo.users SET password_hash = %s WHERE user_id = %s;", (new_hash, user["user_id"]))

        # Update session copy
        user["password_hash"] = new_hash
        st.session_state["auth_user"] = user

        st.success("✅ Password updated successfully!")


def welcome_page():
    user = st.session_state["auth_user"]
    st.title(f"👋 Welcome, {user['username']}!")
    st.write("You are successfully logged in. Click on the [Add New Blog] button to start managing your blogs.")
    
    #if st.button("➡️ Go to Blog Manager", key="btn_blog_manager"):
    #    st.session_state["page"] = "blog"
    #    st.rerun()
    
# ------------------- DB FUNCTIONS ------------------- #
def get_categories():
    return run_query(
        "SELECT category_id, category_name FROM seo.tbl_category_mst ORDER BY category_name;", 
        fetch=True
    )

def get_subcategories(category_id):
    return run_query(
        "SELECT subcategory_id, subcategory_name FROM seo.tbl_subcategory_mst WHERE category_id = %s;", 
        (category_id,), 
        fetch=True
    )

def check_primary_keyword_exists(primary_keyword):
    rows = run_query("""
        SELECT 1 FROM seo.tbl_primary_kw_mst WHERE LOWER(primary_keyword) = LOWER(%s)
        UNION
        SELECT 1 FROM seo.tbl_secondary_kw_mst WHERE LOWER(secondary_kw_name) = LOWER(%s);
    """, (primary_keyword, primary_keyword), fetch=True)
    return bool(rows)

def check_category_exists(category_name):
    rows = run_query("""
        SELECT 1 FROM seo.tbl_category_mst WHERE LOWER(category_name) = LOWER(%s);
    """, (category_name), fetch=True)
    return bool(rows)
    
def insert_blog(topic, title, meta_desc, url, category_name, subcategory_ids, product, inbound_links, primary_kw, secondary_kws, lst_values):
        
    # Primary keyword
    pk_row = run_query("""SELECT primary_kw_id FROM seo.tbl_primary_kw_mst WHERE primary_keyword=%s;""", (primary_kw,), fetch=True)
    if pk_row:
        # primary_kw_id = pk_row[0][0]
        primary_kw_id = pk_row[0]["primary_kw_id"]
    else:
        pk_row = run_query(
            """INSERT INTO seo.tbl_primary_kw_mst (primary_keyword) VALUES (%s) RETURNING primary_kw_id;""",
            (primary_kw,), fetch=True
        )
        primary_kw_id = pk_row[0]["primary_kw_id"]
        
    # st.write("pk_row:", pk_row)
    # if pk_row and len(pk_row) > 0 and len(pk_row[0]) > 0:
       # primary_kw_id = pk_row[0][0]
       # print("DEBUG primary_kw_id:", primary_kw_id)
    # else:
       # raise ValueError(f"Primary keyword insert failed. pk_row={pk_row}")
        
        # primary_kw_id = pk_row[0][0]

    # --- Category Lookup / Insert ---
    cat_row = run_query("""SELECT category_id FROM seo.tbl_category_mst WHERE category_name = %s;""", (category_name,), fetch=True)
    if cat_row:
        category_id = cat_row[0]["category_id"]
    else:
        cat_row = run_query(
            """INSERT INTO seo.tbl_category_mst (category_name) VALUES (%s) RETURNING category_id;""",
            (category_name,), fetch=True
        )
        category_id = cat_row[0]["category_id"]

    # --- Insert Blog ---
    blog_row = run_query("""
        INSERT INTO seo.tbl_blog_mst (topic_name, title_name, meta_description, url, category_id, product_name, primary_kw_id)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
        RETURNING blog_id;
    """, (topic, title, meta_desc, url, category_id, product, primary_kw_id), fetch=True)
    blog_id = blog_row[0]["blog_id"]

    # --- Secondary Keywords ---
    if secondary_kws:
        for skw in secondary_kws:
            if skw.strip():
                run_query("""
                    INSERT INTO seo.tbl_secondary_kw_mst (secondary_kw_name, primary_kw_id)
                    VALUES (%s,%s);
                """, (skw.strip(), primary_kw_id))
    
    # --- SubCategories ---
    if subcategory_ids:
        for subcat in subcategory_ids:
            if subcat.strip():
                run_query("""
                    INSERT INTO seo.tbl_subcategory_mst (subcategory_name, category_id)
                    VALUES (%s,%s);
                """, (subcat.strip(), category_id))
                
    # --- Inbound Links ---
    if inbound_links:
        for link in inbound_links:
            if link.strip():
                run_query(
                    "INSERT INTO seo.tbl_inbound_links (blog_id, inbound_link_url) VALUES (%s,%s);", 
                    (blog_id, link.strip())
                )

    # --- LST ---
    if lst_values:
        for lst in lst_values:
            if lst.strip():
                run_query(
                    "INSERT INTO seo.tbl_lst (blog_id, lst) VALUES (%s,%s);", 
                    (blog_id, lst.strip())
                )

    return blog_id


def get_blogs():
    return run_query("""
        SELECT b.blog_id, b.topic_name, b.title_name, b.meta_description, b.url, c.category_name, b.product_name, pk.primary_keyword,
               --skw.secondary_kw_name, cs.subcategory_name, ls.lst, ib.inbound_link_url
                STRING_AGG(DISTINCT skw.secondary_kw_name, ', ') AS secondary_keywords,
                STRING_AGG(DISTINCT cs.subcategory_name, ', ') AS subcategories,
                STRING_AGG(DISTINCT ls.lst, ', ') AS lst_values,
                STRING_AGG(DISTINCT ib.inbound_link_url, ', ') AS inbound_links
        FROM seo.tbl_blog_mst b
        LEFT JOIN seo.tbl_category_mst c ON b.category_id = c.category_id
        LEFT JOIN seo.tbl_primary_kw_mst pk ON b.primary_kw_id = pk.primary_kw_id
        LEFT JOIN seo.tbl_secondary_kw_mst skw ON skw.primary_kw_id = pk.primary_kw_id
        LEFT JOIN seo.tbl_subcategory_mst cs ON cs.category_id = c.category_id
        LEFT JOIN seo.tbl_lst ls ON ls.blog_id = b.blog_id
        LEFT JOIN seo.tbl_inbound_links ib ON ib.blog_id = b.blog_id
        GROUP BY b.blog_id, b.topic_name, b.title_name, b.meta_description, b.url, c.category_name, b.product_name, pk.primary_keyword
        ORDER BY b.blog_id ;
    """, fetch=True)

def delete_blog(blog_id):
    run_query("DELETE FROM seo.tbl_blog_mst WHERE blog_id = %s;", (blog_id,))


def blog_page():
    user = st.session_state["auth_user"]
    
    # ------------------- SIDEBAR SEARCH ------------------- #

    #st.sidebar.title("Blog Management")
    #action = st.sidebar.radio("Select Action:", ("Add New Blog Details", "View Existing Blog Details"))

    # Clear all input fields
    for key in ["topic", "title", "meta_desc", "url", "category_name", "product", "primary_kw",
                        "subcategories", "secondary_kws", "inbound_links", "lst_values"]:
        if key in st.session_state:
            if isinstance(st.session_state[key], list):
                st.session_state[key] = [""]
            else:
                st.session_state[key] = ""        
        
    st.sidebar.markdown('<h3 style="font-size:14px; color:#333;">🔍 Search by Primary Keyword</h3>', unsafe_allow_html=True)
    #st.sidebar.header("🔍 Search Blog by Primary Keyword")
    search_kw = st.sidebar.text_input("Enter Primary Keyword")

    if search_kw:
        results = run_query("""
        SELECT title_name, url 
        FROM seo.tbl_blog_mst 
        where primary_kw_id in 
        (    
            select distinct primary_kw_id 
            from 
            (     
                SELECT primary_keyword, primary_kw_id 
                FROM seo.tbl_primary_kw_mst 
                WHERE primary_keyword ILIKE %s
                UNION
                SELECT secondary_kw_name, primary_kw_id  
                FROM seo.tbl_secondary_kw_mst
                WHERE secondary_kw_name ILIKE %s
            )
        );""", (f"%{search_kw}%", f"%{search_kw}%"), fetch=True)

        if results:
            st.sidebar.success(f"Found {len(results)} result(s)")

            # Table view
            #result_df = pd.DataFrame(results, columns=["Title", "URL"])
            #st.sidebar.dataframe(result_df)
            
            result_df = pd.DataFrame(results)
            #result_df = result_df.rename(columns={"title_name": "Title","url": "URL"})
            result_df = result_df.rename(columns={"title_name": "Title"})
            st.sidebar.dataframe(result_df)
            

            # Clickable links
            #st.sidebar.markdown("### 🔗 Quick Links")
            #for row in results:
                #primary_kw, url = row
                #st.sidebar.markdown(f"- **{primary_kw}** → [Open Blog]({url})", unsafe_allow_html=True)
        else:
            st.sidebar.warning("No blogs found for this keyword.")
    
    # ------------------- STREAMLIT UI ------------------- #
    st.title("Blog Management System")
    #st.subheader("Blog Data Entry Form")

    # Mode selector
    mode = st.radio("**Select Data Entry Mode:**", ["CSV Upload", "Manual Insert"], horizontal=True)
    
    # ------------------- MANUAL ENTRY ------------------- #
    if mode == "Manual Insert":
          
        # ---------------- Initialize session state ----------------
        for field in ["subcategories", "inbound_links", "secondary_kws", "lst_values"]:
            if field not in st.session_state:
                st.session_state[field] = ""
                
        # Input fields
        #st.subheader("Topic")
        st.markdown('<h3 style="font-size:20px; color:#333;">Topic</h3>', unsafe_allow_html=True)
        topic = st.text_input("", key="key_topic")
        
        st.markdown('<h3 style="font-size:20px; color:#333;">Title</h3>', unsafe_allow_html=True)
        title = st.text_input("", key="key_title")
        
        st.markdown('<h3 style="font-size:20px; color:#333;">Meta Description</h3>', unsafe_allow_html=True)
        meta_desc = st.text_area("", key="key_meta_desc")
        
        st.markdown('<h3 style="font-size:20px; color:#333;">URL</h3>', unsafe_allow_html=True)
        url = st.text_input("", key="key_url")
        
        st.markdown('<h3 style="font-size:20px; color:#333;">Category</h3>', unsafe_allow_html=True)
        category_name = st.text_input("", key="key_category_name")
        
        # ---------------- Multi-item Textareas ----------------
        st.markdown('<h3 style="font-size:20px; color:#333;">SubCategories</h3>', unsafe_allow_html=True)
        st.session_state["subcategories"] = st.text_area(
            "Enter multiple subcategories separated by comma",
            value=st.session_state["subcategories"],
            placeholder="E.g., SEO, Marketing, Content"
        )

        st.markdown('<h3 style="font-size:20px; color:#333;">Product</h3>', unsafe_allow_html=True)
        product = st.text_input("**Product**", key="key_product")

        #st.subheader("Inbound Links")
        st.markdown('<h3 style="font-size:20px; color:#333;">Inbound Links</h3>', unsafe_allow_html=True)
        st.session_state["inbound_links"] = st.text_area(
            "Enter multiple inbound links separated by comma",
            value=st.session_state["inbound_links"],
            placeholder="E.g., https://example.com, https://site.com"
        )
    
        st.markdown('<h3 style="font-size:20px; color:#333;">Primary Keyword</h3>', unsafe_allow_html=True)
        primary_kw = st.text_input("**Primary Keyword**", key="key_primary_kw")

        #st.subheader("Secondary Keywords")
        st.markdown('<h3 style="font-size:20px; color:#333;">Secondary Keyword</h3>', unsafe_allow_html=True)
        st.session_state["secondary_kws"] = st.text_area(
            "Enter multiple secondary keywords separated by comma",
            value=st.session_state["secondary_kws"],
            placeholder="E.g., keyword1, keyword2, keyword3"
        )

        #st.subheader("LST Values")
        st.markdown('<h3 style="font-size:20px; color:#333;">LST Values</h3>', unsafe_allow_html=True)
        st.session_state["lst_values"] = st.text_area(
            "Enter multiple LST values separated by comma",
            value=st.session_state["lst_values"],
            placeholder="E.g., value1, value2, value3"
        )
                
        # Save
        if st.button("Save Blog", key="btn_save_blog"): 
            if not topic or not title or not primary_kw:
                st.error("Topic, Title and Primary Keyword are required.")
            elif check_primary_keyword_exists(primary_kw):
                st.error("Primary keyword already exists. Please change it.")
            #elif check_category_exists(category_name):
            #    st.error("Category already exists. Please change it.")
            else:
                
                subcategories_list = [x.strip() for x in st.session_state["subcategories"].split(",") if x.strip()]
                inbound_links_list = [x.strip() for x in st.session_state["inbound_links"].split(",") if x.strip()]
                secondary_kws_list = [x.strip() for x in st.session_state["secondary_kws"].split(",") if x.strip()]
                lst_values_list = [x.strip() for x in st.session_state["lst_values"].split(",") if x.strip()]

                # Update session_state with parsed lists
                st.session_state["subcategories"] = subcategories_list
                st.session_state["inbound_links"] = inbound_links_list
                st.session_state["secondary_kws"] = secondary_kws_list
                st.session_state["lst_values"] = lst_values_list
                
                insert_blog(
                    topic, title, meta_desc, url, category_name,
                    st.session_state["subcategories"], product,
                    st.session_state["inbound_links"], primary_kw,
                    st.session_state["secondary_kws"], st.session_state["lst_values"]
                )
                st.success("Blog saved successfully!")
                
                
                # Reset form
                st.session_state["subcategories"] = ""
                st.session_state["secondary_kws"] = ""
                st.session_state["inbound_links"] = ""
                st.session_state["lst_values"] = ""
                

# ------------------- CSV UPLOAD ------------------- #
    elif mode == "CSV Upload":
        
        
        
        # Path to your existing CSV file
        file_path = "sample_template.csv"

        # Open the file in binary mode
        with open(file_path, "rb") as f:
            st.download_button(
                label="Download Sample Template For CSV Upload",
                data=f,
                file_name="sample_template.csv",
                mime="text/csv"
            )
            
        st.subheader("Upload CSV for Bulk Insert")    
        uploaded_file = st.file_uploader("Choose a CSV file", type=["csv"])    
        
        st.markdown('<p style="font-size:16px; color:blue;"><b><U>Quick Tip:</U></b> Enter multiple [Subcategories] / [Inbound links] / [Secondary keywords] / [LST values]  separated by comma. (E.g., SEO, Marketing, https://example.com, keyword1, keyword2, Lst value1, Lst value2)</p>', unsafe_allow_html=True)
        
  
        if uploaded_file is not None:
            df = pd.read_csv(uploaded_file)
            
                                                                                                               
            st.write("Preview of uploaded data:")
            st.dataframe(df.head())

            if st.button("Insert All Records", key="btn_bulk_insert"):
                
                missing_required = df[
                    df["Topic"].isna() | df["Title"].isna() | df["Primary Keyword"].isna()
                ]
                
                # Strip whitespace and lowercase for safety
                df["Primary Keyword"] = df["Primary Keyword"].astype(str).str.strip()
                
                # Check for duplicates in DB
                duplicates = []
                for kw in df["Primary Keyword"]:
                    if check_primary_keyword_exists(kw):
                        duplicates.append(kw)
                  
                if not missing_required.empty:
                    st.error(
                        f"❌ Validation failed. {len(missing_required)} row(s) "
                        f"have missing required fields (Topic, Title, Primary Keyword)."
                    )
                    st.dataframe(missing_required)
                
                elif duplicates:
                    st.error(f"Primary keyword(s) already exist in the database: {', '.join(duplicates)}")
                    st.stop()  # Stop further processing, do not insert    
                    
                else:
                    for _, row in df.iterrows():
                        insert_blog(
                            row["Topic"], row["Title"], row["Meta Description"], row["URL"],
                            row["Category"],
                            [row["SubCategory"]] if pd.notna(row.get("SubCategory")) else [],
                            row["Product"],
                            row["Inbound Links"].split(",") if pd.notna(row.get("Inbound Links")) else [],
                            row["Primary Keyword"],
                            row["Secondary Keyword"].split(",") if pd.notna(row.get("Secondary Keyword")) else [],
                            row["LST"].split(",") if pd.notna(row.get("LST")) else []
                        )
                    st.success(f"✅ {len(df)} records inserted successfully!")
                    
def view_blogs():
    #st.title("Existing Blogs")
    st.subheader("Existing Blogs")
    blogs = get_blogs()

    if blogs:
        blog_df = pd.DataFrame(blogs).reset_index(drop=True)

        blog_df = blog_df.rename(columns={
            "blog_id": "ID",  # keep internal
            "topic_name": "Topic",
            "title_name": "Title",
            "meta_description": "Meta Description",
            "url": "URL",
            "category_name": "Category",
            "subcategories": "SubCategory",
            "product_name": "Product",
            "inbound_links": "Inbound Links",
            "primary_keyword": "Primary Keyword",
            "secondary_keywords": "Secondary Keyword",
            "lst_values": "LST Value"
        })
        blog_df.insert(0, "S.No", range(1, len(blog_df) + 1))
        
        blog_df=blog_df[["S.No","ID","Topic","Title","Meta Description","URL","Category","SubCategory","Product","Inbound Links","Primary Keyword","Secondary Keyword","LST Value"]]
        

        # Add a checkbox column for deletion
        blog_df["Delete?"] = False

        # Prepare dataframe for display (exclude ID)
        display_df = blog_df.drop(columns=["ID"])

        # Editable dataframe with checkboxes
        edited_df = st.data_editor(
            display_df,
            use_container_width=True,
            hide_index=True,
            num_rows="dynamic",
            disabled=[
                "S.No", "Topic", "Title", "Meta Description", "URL", 
                "Category", "SubCategory", "Product", "Inbound Links", 
                "Primary Keyword", "Secondary Keyword", "LST"
            ]
        )

        # Map back edited rows to original dataframe (to keep IDs)
        merged_df = blog_df.copy()
        merged_df["Delete?"] = edited_df["Delete?"]

        # Section for delete action
        st.markdown("---")
        st.subheader("🗑️ Delete Blogs")

        to_delete = merged_df[merged_df["Delete?"] == True]

        if not to_delete.empty:
            st.warning(f"{len(to_delete)} blog(s) selected for deletion.")
            st.dataframe(to_delete[["Topic", "Title", "Primary Keyword"]])

            confirm = st.checkbox("Yes, I want to delete the selected blogs permanently")

            if st.button("Delete Selected"):
                if confirm:
                    for _, row in to_delete.iterrows():
                        delete_blog(row["ID"])  # uses hidden ID
                    st.success(f"🗑️ Deleted {len(to_delete)} blog(s).")
                    st.rerun()
                else:
                    st.info("⚠️ Please confirm deletion before proceeding.")
        else:
            st.info("No blogs selected for deletion.")

    else:
        st.info("No blogs found.")

        
def main_controller():
    if not st.session_state["authenticated"]:
        # Show only login/register before authentication
        #st.sidebar.title("User Access")
        #page = st.sidebar.radio("Select:", ["Login", "Register"])
        #page = st.sidebar.radio("Select:", ["Login"])
        page = "Login"
        if page == "Register":
            registration_page()
        else:
            login_page()
        st.stop()
    else:
        
        
        
        # ---------------- Sidebar Menu ----------------
        with st.sidebar:
            #st.markdown("## 📝 Blog Dashboard")
            # After login → sidebar shows hello + logout only
            user = st.session_state["auth_user"]
            st.sidebar.markdown(f"👋 Hello, **{user['username']}**")
            
            if "show_logout_confirm" not in st.session_state:
                st.session_state.show_logout_confirm = False
            
            selected = option_menu(
                menu_title=None,  # No title since we already have one
                options=["Add New Blog", "View Blog", "Change Password", "Logout"],
                icons=["plus-square", "eye", "key", "box-arrow-right"],  # Bootstrap icons
                menu_icon="cast",
                default_index=0,
                orientation="vertical",
                styles={
                    "container": {"padding": "6px", "background-color": "#f0f2f6"},
                    "icon": {"color": "#0d6efd", "font-size": "18px"},
                    "nav-link": {"font-size": "14px", "text-align": "left", "margin":"0px", "--hover-color": "#dde1f2"},
                    "nav-link-selected": {"background-color": "#0d6efd", "color": "white", "font-size": "14px"},
                }
            )
        
        
        
        # if st.sidebar.button("👉 Add New Blog", key="btn_blog_manager2"):
            # st.session_state["page"] = "blog"
            # st.rerun()
            
        # if st.sidebar.button("➡️ View Blogs", key="btn_blog_manager3"):
            # st.session_state["page"] = "view_blogs"
            # st.rerun()
            
        # if st.sidebar.button("🔑 Change Password"):
            # st.session_state["page"] = "change_pw"
            # st.rerun()
    
        # if st.sidebar.button("🚪 Logout"):
            # st.session_state["authenticated"] = False
            # st.session_state["auth_user"] = None
            # st.session_state["awaiting_otp"] = False
            # st.session_state["page"] = "welcome"
            # st.rerun()

        # Decide which page to show
        # if "page" not in st.session_state:
            # st.session_state["page"] = "welcome"

        # if st.session_state["page"] == "welcome":
            # welcome_page()
        
        # if st.session_state["page"] == "blog":
            # blog_page()
            
        # if st.session_state["page"] == "change_pw":
            # change_password_page()
        
        # if st.session_state["page"] == "view_blogs":
            # view_blogs()
            
        # ---------------- Main Content ----------------
        if selected == "Add New Blog":
            #st.header("Add New Blog")
            #st.write("Form to add a new blog goes here...")
            blog_page()

        elif selected == "View Blog":
            #st.header("View Blog")
            #st.write("Table or list of blogs goes here...")
            view_blogs()

        elif selected == "Change Password":
            #st.header("Change Password")
            #st.write("Form to change password goes here...")
            change_password_page()

        elif selected == "Logout":
            # st.session_state["authenticated"] = False
            # st.session_state["auth_user"] = None
            # st.session_state["awaiting_otp"] = False
            # st.session_state["page"] = "welcome"
            # st.rerun()
            
            
            if not st.session_state.show_logout_confirm:
                st.session_state.show_logout_confirm = True

            if st.session_state.show_logout_confirm:
                with st.container():
                    st.warning("Are you sure you want to logout?")
                    col1, col2 = st.columns(2)
                    if col1.button("Yes, Logout"):
                        st.session_state["authenticated"] = False
                        st.session_state["auth_user"] = None
                        st.session_state["awaiting_otp"] = False
                        st.session_state["page"] = "welcome"
                        st.rerun()
                    if col2.button("Cancel"):
                        st.session_state.show_logout_confirm = False
                        st.info("Logout cancelled.")
            
           
main_controller()

