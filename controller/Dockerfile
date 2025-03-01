FROM maven:latest as build 
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline
COPY src ./src
RUN mvn clean package


FROM openjdk:24-ea-17-slim as run
COPY --from=build /app/target/*.jar app.jar
EXPOSE 9000
CMD ["java", "-jar", "app.jar"]



