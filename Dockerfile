# Use an official Python runtime as a parent image
FROM python:3.11

# Set the working directory in the container to /app
WORKDIR /app

# Add the current directory contents into the container at /app
ADD . /app

RUN pip install --no-cache-dir -U pip pre-commit pip-tools

# Install the application
RUN pip install --no-cache-dir -r requirements.txt

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r src/python-fastui/requirements/all.txt

# Install the application
RUN pip install --no-cache-dir -e src/python-fastui

# Install Node.js and npm
RUN apt-get update && apt-get install -y nodejs npm

# Install JavaScript dependencies
RUN npm install

# Make port 8000 available to the world outside this container
EXPOSE 8000

# Run the application when the container launches
CMD ["uvicorn", "frontend:app", "--reload", "--reload-dir", ".", "--host", "0.0.0.0"]