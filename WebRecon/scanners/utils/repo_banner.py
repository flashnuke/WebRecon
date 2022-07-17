from .default_values import OutputColors


def get_banner():
    return _banner


_banner = f"""
                         {OutputColors.Green}{OutputColors.BOLD} __        __{OutputColors.White}{OutputColors.YELLOW}   _    {OutputColors.White}{OutputColors.Green}{OutputColors.BOLD} ____ {OutputColors.White}{OutputColors.YELLOW}                     
                          {OutputColors.Green}{OutputColors.BOLD}\ \      / /{OutputColors.White}{OutputColors.YELLOW}__| |__ {OutputColors.White}{OutputColors.Green}{OutputColors.BOLD}|  _ \{OutputColors.White}{OutputColors.YELLOW} ___  ___ ___  _ __  {OutputColors.White}                          
                           {OutputColors.Green}{OutputColors.BOLD}\ \ /\ / /{OutputColors.White}{OutputColors.YELLOW} _ \\ '_ \{OutputColors.White}{OutputColors.Green}{OutputColors.BOLD}| |_){OutputColors.White}{OutputColors.YELLOW} / _ \/ __/ _ \| '_ \{OutputColors.White}                           
                            {OutputColors.Green}{OutputColors.BOLD}\ V  V /{OutputColors.White}{OutputColors.YELLOW}  __/ |_) {OutputColors.White}{OutputColors.Green}{OutputColors.BOLD}|  _ <{OutputColors.White}{OutputColors.YELLOW}  __/ (_| (_) | | | |{OutputColors.White}                          
                             {OutputColors.Green}{OutputColors.BOLD}\_/\_/{OutputColors.White}{OutputColors.YELLOW} \___|_.__/{OutputColors.White}{OutputColors.Green}{OutputColors.BOLD}|_| \_\{OutputColors.White}{OutputColors.YELLOW}___|\___\___/|_| |_|{OutputColors.White}                          """
