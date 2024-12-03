-- Drop existing tables, triggers, and enum types if they exist
DROP TABLE IF EXISTS urls_solutions CASCADE;
DROP TABLE IF EXISTS solutions CASCADE;
DROP TABLE IF EXISTS cves_urls CASCADE;
DROP TABLE IF EXISTS cves CASCADE;
DROP TABLE IF EXISTS vendors CASCADE;
DROP TABLE IF EXISTS products CASCADE;
DROP TABLE IF EXISTS cves_products CASCADE;
DROP TABLE IF EXISTS cves_vendors CASCADE;
DROP TABLE IF EXISTS cves_cwes CASCADE;
DROP TABLE IF EXISTS cwes CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS organizations CASCADE;
DROP TABLE IF EXISTS admins CASCADE;
DROP TABLE IF EXISTS alerts CASCADE;
DROP TABLE IF EXISTS plan_types;

-- Drop existing enum types if they exist
DROP TYPE IF EXISTS role_enum;
DROP TYPE IF EXISTS plan_type_enum;

-- Enum Types for Role and Plan Types
CREATE TYPE role_enum AS ENUM ('admin', 'tester', 'developer');
CREATE TYPE plan_type_enum AS ENUM ('solo', 'starter', 'enterprise');

-- Create the plan_types table
CREATE TABLE plan_types(
	plan_id SERIAL PRIMARY KEY,
    plan_name VARCHAR(50),
    plan_price FLOAT,
	immediate_notification BOOLEAN,
	max_users INT NOT NULL,
	max_subscriptions INT NOT NULL
);

-- Create the roles table
CREATE TABLE roles(
	role_id SERIAL primary key,
    role_name VARCHAR(50)
);

-- Create the admins table
CREATE TABLE admins (
    admin_id SERIAL PRIMARY KEY,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    reset_pswd_token VARCHAR(50),
    role INT REFERENCES roles(role_id)
);

-- Create the organizations table
CREATE TABLE organizations (
    organization_id SERIAL PRIMARY KEY,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name VARCHAR(100) NOT NULL,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(100) NOT NULL,
    plan_type INT REFERENCES plan_types(plan_id),
    max_subscriptions INT,
    immediate_notification BOOLEAN
);

-- Create the users table
CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    organization_id INT REFERENCES organizations(organization_id),
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL
);

-- Create the cwes table
CREATE TABLE cwes (
    id SERIAL PRIMARY KEY,
    cwe_id VARCHAR(50) UNIQUE NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name VARCHAR(250),
    description TEXT
);

-- Create the vendors table
CREATE TABLE vendors (
    vendor_id SERIAL PRIMARY KEY,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    vend_name VARCHAR(100) NOT NULL
);

-- Create the products table
CREATE TABLE products (
    product_id SERIAL PRIMARY KEY,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    product_name VARCHAR(100) NOT NULL,
    vendor_id INT REFERENCES vendors(vendor_id)
);

-- Create the cves table
CREATE TABLE cves (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) UNIQUE NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    summary TEXT,
    cvss2 FLOAT,
    cvss3 FLOAT
);

-- Create the cves_urls table
CREATE TABLE cves_urls (
    url_id SERIAL PRIMARY KEY,
    cve_id INT REFERENCES cves(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    content TEXT
);

-- Create the solutions table
CREATE TABLE solutions (
    id SERIAL PRIMARY KEY,
    cve_id INT REFERENCES cves(id) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    solution TEXT
);

-- Create the urls_solutions junction table
CREATE TABLE urls_solutions (
    solution_id INT REFERENCES solutions(id) ON DELETE CASCADE,
    url_id INT REFERENCES cves_urls(url_id) ON DELETE CASCADE,
    PRIMARY KEY (solution_id, url_id)
);

-- Create the cves_products table
CREATE TABLE cves_products (
    cve_id INT REFERENCES cves(id),
    product_id INT REFERENCES products(product_id),
    PRIMARY KEY (cve_id, product_id)
);

-- Create the cves_vendors table
CREATE TABLE cves_vendors (
    cve_id INT REFERENCES cves(id),
    vendor_id INT REFERENCES vendors(vendor_id),
    PRIMARY KEY (cve_id, vendor_id)
);

-- Create the cves_cwes table
CREATE TABLE cves_cwes (
    cve_id INT REFERENCES cves(id),
    cwe_id INT REFERENCES cwes(id),
    PRIMARY KEY (cve_id, cwe_id)
);

-- Create the users_products table
CREATE TABLE users_products (
    user_id INT REFERENCES users(user_id),
    product_id INT REFERENCES products(product_id),
    PRIMARY KEY (user_id, product_id)
);

-- Create the users_vendors table
CREATE TABLE users_vendors (
    user_id INT REFERENCES users(user_id),
    vendor_id INT REFERENCES vendors(vendor_id),
    PRIMARY KEY (user_id, vendor_id)
);

-- Create the users_cwes table
CREATE TABLE users_cwes (
    user_id INT REFERENCES users(user_id),
    cwe_id INT REFERENCES cwes(id),
    PRIMARY KEY (user_id, cwe_id)
);

-- Create a table to track alerts for CVEs
CREATE TABLE alerts (
    alert_id SERIAL PRIMARY KEY,
    cve_id INT REFERENCES cves(id) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_new_cve BOOLEAN DEFAULT TRUE,
    is_treated BOOLEAN DEFAULT FALSE,
    last_alert_id INT
);

-- Trigger function to notify on new CVE
CREATE OR REPLACE FUNCTION notify_new_cve()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify('new_cve', NEW.cve_id::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to call the function on insert for new CVEs
CREATE TRIGGER notify_cve_insert
AFTER INSERT ON cves
FOR EACH ROW
EXECUTE FUNCTION notify_new_cve();

-- Trigger function to clean solutions when URLs are updated
CREATE OR REPLACE FUNCTION clean_solution_on_url_update()
RETURNS TRIGGER AS $$
BEGIN
    -- Delete existing solutions if URLs are updated
    DELETE FROM urls_solutions
    WHERE solution_id IN (SELECT id FROM solutions WHERE cve_id = NEW.cve_id);

    -- Optional: Trigger AI-based solution rebuilding here if needed

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to clean solution when a URL is updated (insert or delete)
CREATE TRIGGER trg_clean_solution_on_url_update
AFTER INSERT OR DELETE ON cves_urls
FOR EACH ROW
EXECUTE FUNCTION clean_solution_on_url_update();

-- Trigger function to add new URLs and handle the solution linking
CREATE OR REPLACE FUNCTION update_solution_urls()
RETURNS TRIGGER AS $$
BEGIN
    -- Add new URL to the solutions table (new URL linked to existing solution)
    INSERT INTO urls_solutions (solution_id, url_id)
    SELECT id, NEW.url_id
    FROM solutions
    WHERE cve_id = NEW.cve_id;

    -- Optional: Rebuild the solution based on the new URLs (AI-based process here)

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to add new URLs to solutions when a new URL is inserted
CREATE TRIGGER trg_update_solution_urls
AFTER INSERT ON cves_urls
FOR EACH ROW
EXECUTE FUNCTION update_solution_urls();

-- Trigger function to remove URLs from solutions when they are deleted
CREATE OR REPLACE FUNCTION remove_solution_urls()
RETURNS TRIGGER AS $$
BEGIN
    -- Remove the URL from solutions if it is deleted
    DELETE FROM urls_solutions
    WHERE url_id = OLD.url_id
    AND solution_id IN (SELECT id FROM solutions WHERE cve_id = OLD.cve_id);

    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

-- Trigger to remove URLs from solutions when a URL is deleted
CREATE TRIGGER trg_remove_solution_urls
AFTER DELETE ON cves_urls
FOR EACH ROW
EXECUTE FUNCTION remove_solution_urls();

-- Trigger function to handle solution updates when new URLs are linked to a CVE
CREATE OR REPLACE FUNCTION handle_solution_update()
RETURNS TRIGGER AS $$
BEGIN
    -- Check if there are any new URLs linked to the CVE and add them to solutions
    IF EXISTS (SELECT 1 FROM cves_urls WHERE cve_id = NEW.cve_id) THEN
        -- Add or remove URLs as needed (handled by triggers above)
        NULL;  -- Placeholder for any additional operations you might want to add
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to handle solution update after new URLs are linked to a CVE
CREATE TRIGGER trg_handle_solution_update
AFTER INSERT OR UPDATE ON cves
FOR EACH ROW
EXECUTE FUNCTION handle_solution_update();
