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
# CMD ["mvn", "exec:java", "-Dexec.mainClass=com.example.Main"]
CMD ["java",\
#   "-Djavax.net.ssl.keyStore=/app/keystore.jks",\
#   "-Djavax.net.ssl.keyStorePassword=password",\
  "-Djavax.net.ssl.trustStore=/app/truststore.p12",\
  "-Djavax.net.ssl.trustStorePassword=password",\
  "-Djavax.net.ssl.trustStoreType=PKCS12",\
  "-jar",\
  "/app/target/cauth-1.0-SNAPSHOT.jar"\
]
