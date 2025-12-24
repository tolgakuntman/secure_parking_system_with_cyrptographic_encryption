# Use Eclipse Temurin JDK 17 (OpenJDK replacement)
FROM eclipse-temurin:17-jdk

# Install Maven
RUN apt-get update && \
    apt-get install -y maven && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy the entire project
COPY . .

# Build the project
RUN mvn clean package -DskipTests

# Run the application
# No need for truststore - fake-cauth generates its own self-signed CA at runtime
CMD ["java", "-jar", "/app/target/fake-cauth-1.0-SNAPSHOT.jar"]
