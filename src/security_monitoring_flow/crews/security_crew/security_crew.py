# crews/security_crew/security_crew.py
from crewai import Agent, Crew, Process, Task, LLM
from crewai.project import CrewBase, agent, crew, task
from tools.custom_tool import URLAnalyzerTool, SOCCommunicationTool, GatekeeperTool

@CrewBase
class SecurityCrew():
    """Security monitoring crew for URL threat analysis"""
    
    agents_config = 'config/agents.yaml'
    tasks_config = 'config/tasks.yaml'

    ollama_llm = LLM(
        model="ollama/mistral:7b-instruct-q4_0"
    )
    
    @agent
    def url_analyzer_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['url_analyzer_agent'],
            verbose=True,
            tools=[URLAnalyzerTool()],
            allow_delegation=False,
            llm=self.ollama_llm,
            step_callback=lambda step: print(f"Agent step: {step.action}") if hasattr(step, 'action') else None,
            system_message="""
            TOOL USAGE INSTRUCTIONS:
            You have exactly ONE tool: url_analyzer

            CORRECT format:
            Thought: I need to analyze this URL for security threats
            Action: url_analyzer
            Action Input: {"url": "https://example.com"}
            Observation: [tool result]

            WRONG formats (DO NOT USE):
            - Action: Analyze the URL using the url_analyzer tool
            - Action: Continue to analyze the URL using the url_analyzer tool  
            - Action: Use url_analyzer to check the URL

            Action name must be EXACTLY: url_analyzer
            """
        )
    
    @agent  
    def soc_communication_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['soc_communication_agent'],
            verbose=True,
            tools=[SOCCommunicationTool()],
            allow_delegation=False,
            llm=self.ollama_llm,
            system_message="""
            TOOL USAGE INSTRUCTIONS:
            You have exactly ONE tool: soc_communicator

            CORRECT format:
            Thought: I need to send analysis to SOC admin
            Action: soc_communicator
            Action Input: {"analysis_data": "analysis results here"}
            Observation: [tool result]

            Action name must be EXACTLY: soc_communicator
            """
        )
    
    @agent
    def gatekeeper_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['gatekeeper_agent'],
            verbose=True,
            tools=[GatekeeperTool()],
            allow_delegation=False,
            llm=self.ollama_llm,
            system_message="""
            TOOL USAGE INSTRUCTIONS:
            You have exactly ONE tool: gatekeeper_monitor

            CORRECT format:
            Thought: I need to make final security decision
            Action: gatekeeper_monitor
            Action Input: {"context": "combined analysis results"}
            Observation: [tool result]

            Action name must be EXACTLY: gatekeeper_monitor
            """
        )
    
    @task
    def url_analysis_task(self) -> Task:
        return Task(
            config=self.tasks_config['url_analysis_task'],
            agent=self.url_analyzer_agent()
        )
    
    @task
    def soc_communication_task(self) -> Task:
        return Task(
            config=self.tasks_config['soc_communication_task'], 
            agent=self.soc_communication_agent(),
            context=[self.url_analysis_task()]  # ✅ Use context instead of template variables
        )
    
    @task
    def gatekeeper_monitoring_task(self) -> Task:
        return Task(
            config=self.tasks_config['gatekeeper_monitoring_task'],
            agent=self.gatekeeper_agent(),
            context=[self.url_analysis_task(), self.soc_communication_task()]  # ✅ Access both previous outputs
        )
    
    @crew
    def crew(self) -> Crew:
        """Creates the security monitoring crew"""
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,  # ✅ Sequential ensures proper order
            verbose=True
        )
