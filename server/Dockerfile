# Use an official Python runtime as the base image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container
COPY . .

# Install any needed dependencies
RUN pip install flask  # Add other dependencies if needed

# Expose port 9099
EXPOSE 9099

# Run the Python server
CMD ["python", "server.py"]