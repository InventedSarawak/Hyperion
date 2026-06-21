### **Phase 1: The "Iron Core" (Weeks 1-2)**

_Goal: A boring system that just moves data from A to B._

- **Week 1: The Skeleton**
- **Setup:** Initialize the Git repo. Set up the folder structure for a Monorepo (or separate repos if you prefer).
- **Infrastructure:** Write the `docker-compose.yml` file. Spin up **PostgreSQL**, **Redis**, and **Kafka**.
- **Go Service 1 (Ingestion):** Write a simple Go program that hits the GitHub API (public events) every 10 seconds and prints the JSON to the console.
- **Kafka Integration:** Modify the Go program to push that JSON into a Kafka topic named `raw-github-events`.

- **Week 2: The Consumer & Storage**
- **Go Service 2 (Processor):** Write a second Go program that listens to the `raw-github-events` Kafka topic.
- **Database:** Design the basic SQL schema in **PostgreSQL**.
- **Logic:** The Processor reads the Kafka message -> Extracts `repo_name` and `url` -> Inserts it into Postgres.
- **Win:** You now have a working End-to-End pipeline. (API -> Kafka -> Go -> DB).

---

### **Phase 2: The "Intelligence Layer" (Weeks 3-4)**

_Goal: Making the data searchable and connected._

- **Week 3: Search & Vectors**
- **Infrastructure:** Add **Elasticsearch** and **Qdrant** to your Docker Compose.
- **Go Service 3 (Indexer):** Create a worker that reads from Kafka (a new consumer group) and pushes data into Elasticsearch.
- **Vector Logic:** Use a simple library (or external API like OpenAI/HuggingFace) to generate an "embedding" for the commit messages and store them in Qdrant.

- **Week 4: The Graph**
- **Infrastructure:** Add **Neo4j** to Docker Compose.
- **Graph Logic:** Update the Processor to extract "relationships."
- _If commit mentions "Fixes #123", create an edge: `(Commit) -> [FIXES] -> (Issue)`._

- **Win:** You now have "Polyglot Persistence." Your data is flowing into 4 different DBs automatically.

---

### **Phase 3: The "Interface & Polish" (Weeks 5-6)**

_Goal: Making it usable for humans._

- **Week 5: The API Layer**
- **gRPC:** Define your `.proto` files. Create a `SearchService` that queries Elasticsearch and Qdrant.
- **GraphQL:** Set up **gqlgen**. Create a resolver that calls your gRPC service.
- **The Query:** Test a query like `query { search(term: "log4j") { repo_name, similarity_score } }`.

- **Week 6: The TUI (The "Face")**
- **Bubble Tea:** Initialize the TUI app.
- **Connection:** Connect the TUI to your GraphQL (or gRPC) endpoint.
- **UI:** Build a simple list view that updates in real-time.
- **Win:** You can now type in your terminal and see live data from your complex backend.

---

### **Phase 4: The "DevOps & Resume Polish" (Weeks 7-8)**

_Goal: Making it look professional and deployable._

- **Week 7: The "SRE" Week**
- **Observability:** Add **OpenTelemetry** tracing to all your Go services.
- **Dashboards:** Spin up **Grafana** and **Jaeger**.
- **Visuals:** Create a screenshot of a "Trace" passing through 5 microservices. (This is _gold_ for interviews).

- **Week 8: Kubernetes & Documentation**
- **K8s:** Write the Helm charts. Deploy the whole stack to a local **K3s** cluster.
- **ArgoCD:** Set up a GitOps pipeline that syncs your repo to the cluster.
- **README:** Write a killer `README.md` with architecture diagrams (using Mermaid.js), screenshots of the TUI, and instructions on how to run it.
