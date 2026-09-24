import streamlit as st
import whois


def normalize_value(value):

    if value is None:
        return None

    if isinstance(value, (list, tuple)):
        return [
            str(x) for x in value
            if x is not None
        ]

    return str(value)


@st.cache_data(ttl=3600)
def lookup_whois(domain):

    try:
        data = whois.whois(domain)

        return {
            "available": True,
            "registrar": normalize_value(data.registrar),
            "creation_date": normalize_value(data.creation_date),
            "expiration_date": normalize_value(data.expiration_date),
            "updated_date": normalize_value(data.updated_date),
            "status": normalize_value(data.status),
            "nameservers": normalize_value(data.name_servers),
            "organization": normalize_value(data.org),
            "country": normalize_value(data.country),
            "error": None
        }

    except Exception as e:

        return {
            "available": False,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "status": None,
            "nameservers": None,
            "organization": None,
            "country": None,
            "error": f"WHOIS unavailable: {e}"
        }
