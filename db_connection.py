import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
import os
import streamlit as st

# Load environment variables from .env
load_dotenv()

DB_HOST = st.secrets["postgres"]["host"]
DB_NAME = st.secrets["postgres"]["dbname"]
DB_USER = st.secrets["postgres"]["user"]
DB_PASS = st.secrets["postgres"]["password"]
DB_PORT = st.secrets["postgres"]["port"]

# Cache only connection parameters, not the connection object itself
@st.cache_resource
def get_db_params():
    return {
        "host":DB_HOST,
        "dbname":DB_NAME,
        "user":DB_USER,
        "password":DB_PASS,
        "port":DB_PORT,
        "cursor_factory":RealDictCursor 
    }

def get_connection():
    params = get_db_params()
    return psycopg2.connect(**params)
